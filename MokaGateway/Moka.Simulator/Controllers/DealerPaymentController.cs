using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Moka.Contracts.Payments;
using Moka.Contracts.Settings;
using Moka.Simulator.Data;
using Moka.Simulator.Models;
using Moka.Simulator.Services;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Moka.Simulator.Controllers;

public class DealerPaymentController : Controller
{
    private readonly IConfiguration _config;
    private readonly ILogger<DealerPaymentController> _logger;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly MokaSettings _settings;
    private readonly IOrderService _orders;
    private readonly SimulatorDbContext _db;
    private readonly ITestDataService _testData;

    public DealerPaymentController(
        IConfiguration config,
        ILogger<DealerPaymentController> logger,
        IHttpClientFactory httpClientFactory,
        IOptions<MokaSettings> settings,
        SimulatorDbContext db,
        IOrderService orders,
        ITestDataService testData)
    {
        _config = config;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _settings = settings.Value;
        _db = db;
        _orders = orders;
        _testData = testData;
    }

    [HttpGet]
    public IActionResult Create()
    {
        DealerPaymentInputModel model = BuildNewModel();
        model.TestCards = _testData.GetTestCards();
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(DealerPaymentInputModel model)
    {
        if (!ModelState.IsValid)
        {
            PopulateLists(model);
            model.TestCards = _testData.GetTestCards();
            return View(model);
        }

        string mode = _settings.Mode ?? _config["Moka:Mode"] ?? "Test";
        string dealerCode = _settings.DealerCode ?? "DEALER";
        string username = _settings.Username ?? "apiuser";
        string password = _settings.Password ?? "apipass";
        string? postUrl = _settings.PostUrl ?? _config["Moka:PostUrl"];
        string? redirectUrl = _settings.RedirectUrl ?? _config["Moka:RedirectUrl"];
        if (string.IsNullOrWhiteSpace(postUrl))
        {
            ModelState.AddModelError(string.Empty, "PostUrl is not configured.");
            PopulateLists(model);
            model.TestCards = _testData.GetTestCards();
            return View(model);
        }

        DateTime now = DateTime.UtcNow;
        string otherTrxCode = $"VN{now:ddMMyyyyHHmmssfff}";
        string cardNumber = (model.CardNumber ?? string.Empty).Replace(" ", string.Empty);
        string clientIp = mode.Equals("Test", StringComparison.OrdinalIgnoreCase) ? "127.0.0.1" : HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;

        DealerPaymentServicePaymentRequest request = new DealerPaymentServicePaymentRequest
        {
            PaymentDealerAuthentication = new PaymentDealerAuthentication
            {
                DealerCode = dealerCode,
                Username = username,
                Password = password,
                CheckKey = Sha256(dealerCode + "MK" + username + "PD" + password)
            },
            PaymentDealerRequest = new PaymentDealerRequest
            {
                CardHolderFullName = model.CardHolderFullName,
                CardNumber = cardNumber,
                ExpMonth = model.ExpMonth,
                ExpYear = model.ExpYear,
                CvcNumber = model.CvcNumber,
                Amount = model.Amount,
                Currency = "TL",
                InstallmentNumber = model.InstallmentNumber <= 0 ? 1 : model.InstallmentNumber,
                OtherTrxCode = otherTrxCode,
                ClientIP = clientIp,
                RedirectUrl = redirectUrl,
                ReturnHash = 1
            }
        };

        JsonSerializerOptions jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = null, PropertyNameCaseInsensitive = true };
        try
        {
            HttpClient client = _httpClientFactory.CreateClient();
            using HttpRequestMessage msg = new HttpRequestMessage(HttpMethod.Post, postUrl);
            msg.Content = new StringContent(JsonSerializer.Serialize(request, jsonOptions), Encoding.UTF8, "application/json");
            if (postUrl.Contains("localhost", StringComparison.OrdinalIgnoreCase))
                msg.Headers.Add("X-API-KEY", _config["ApiKeys:Primary"] ?? "dev-key");
            using HttpResponseMessage response = await client.SendAsync(msg);
            
            if (!response.IsSuccessStatusCode)
            {
                ModelState.AddModelError(string.Empty, $"Gateway error: {(int)response.StatusCode} {response.ReasonPhrase}");
                PopulateLists(model);
                model.TestCards = _testData.GetTestCards();
                return View(model);
            }

            string responseJson = await response.Content.ReadAsStringAsync();
            DealerPaymentServicePaymentResult result = JsonSerializer.Deserialize<DealerPaymentServicePaymentResult>(responseJson, jsonOptions) ?? new DealerPaymentServicePaymentResult();
            foreach (string warning in result.Warnings) ModelState.AddModelError(string.Empty, warning);
           
            if (string.Equals(result.ResultCode, "Success", StringComparison.OrdinalIgnoreCase) && result.Data?.Url is string url && !string.IsNullOrWhiteSpace(url))
            {
                _db.PaymentSessions.Add(new Data.PaymentSession { OtherTrxCode = otherTrxCode, CodeForHash = result.Data.CodeForHash ?? string.Empty, Amount = model.Amount, Currency = "TL", MaskedCard = MaskCard(cardNumber) });
                await _db.SaveChangesAsync();
                string simulatedHash = Compute3DHash(dealerCode, otherTrxCode, result.Data.CodeForHash ?? string.Empty, password);
                model.PostUrl = url; // bank3D page
                model.Trx = otherTrxCode;
                model.Hash = simulatedHash;
                return View("GatewayRedirect", model);
            }

            if (!string.IsNullOrWhiteSpace(result.ResultCode)) ModelState.AddModelError(string.Empty, _testData.GetErrorMessage(result.ResultCode));
            if (!string.IsNullOrWhiteSpace(result.ResultMessage)) ModelState.AddModelError(string.Empty, result.ResultMessage);
        }
        catch (TaskCanceledException)
        {
            ModelState.AddModelError(string.Empty, "Ýstek zaman aþýmýna uðradý.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Payment request failed");
            ModelState.AddModelError(string.Empty, "Beklenmeyen bir hata oluþtu.");
        }

        PopulateLists(model);
        model.TestCards = _testData.GetTestCards();
        return View(model);
    }

    [HttpGet, HttpPost]
    public async Task<IActionResult> Callback(string? trx, string? resultCode = null, string? resultMessage = null, string? hash = null)
    {
        IFormCollection? form = Request.HasFormContentType ? Request.Form : null;
        string? hashValue = form?["hashValue"].FirstOrDefault();
        string? trxCode = form?["trxCode"].FirstOrDefault();
        string? otherTrx = form?["OtherTrxCode"].FirstOrDefault();
        trx ??= otherTrx ?? Request.Query["trx"].FirstOrDefault();
        hash ??= hashValue ?? Request.Query["hash"].FirstOrDefault();
        resultCode ??= form?["resultCode"].FirstOrDefault() ?? Request.Query["resultCode"].FirstOrDefault();
        resultMessage ??= form?["resultMessage"].FirstOrDefault() ?? Request.Query["resultMessage"].FirstOrDefault();

        Data.PaymentSession? session = null;
        if (!string.IsNullOrWhiteSpace(trx))
            session = _db.PaymentSessions.FirstOrDefault(s => s.OtherTrxCode == trx);

        bool verified = false;
        string localExpected = string.Empty;
        if (session != null && !string.IsNullOrWhiteSpace(hash))
        {
            string dealerCode = _settings.DealerCode ?? string.Empty;
            string password = _settings.Password ?? string.Empty;
            localExpected = Compute3DHash(dealerCode, trx!, session.CodeForHash, password);
            verified = string.Equals(localExpected, hash, StringComparison.OrdinalIgnoreCase);
        }

        bool apiVerified = false;
        string? apiExpected = null;
        if (session != null && !string.IsNullOrWhiteSpace(_settings.PostUrl) && !string.IsNullOrWhiteSpace(trx) && !string.IsNullOrWhiteSpace(hash))
        {
            try
            {
                string verifyUrl = _settings.PostUrl!.EndsWith("/pay", StringComparison.OrdinalIgnoreCase)
                    ? _settings.PostUrl[..^3] + "verify3d"
                    : _settings.PostUrl!.Replace("pay", "verify3d");
                Dictionary<string, string> dict = new Dictionary<string, string>
                {
                    { "trx", trx! },
                    { "hash", hash! },
                    { "dealerCode", _settings.DealerCode ?? string.Empty },
                    { "codeForHash", session!.CodeForHash }
                };
                HttpClient client = _httpClientFactory.CreateClient();
                using HttpResponseMessage resp = await client.PostAsync(verifyUrl, new FormUrlEncodedContent(dict));
                if (resp.IsSuccessStatusCode)
                {
                    string js = await resp.Content.ReadAsStringAsync();
                    using JsonDocument doc = JsonDocument.Parse(js);
                    apiVerified = doc.RootElement.TryGetProperty("verified", out JsonElement v) && v.GetBoolean();
                    if (doc.RootElement.TryGetProperty("expected", out JsonElement exp)) apiExpected = exp.GetString();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Remote verify failed for trx={trx}", trx);
            }
        }

        int? orderId = null;
        if (verified && session != null)
        {
            session.TrxCode = trxCode ?? session.TrxCode;
            Order order = _orders.Create(trx!, session.TrxCode ?? string.Empty, session.Amount, session.Currency, session.MaskedCard);
            orderId = order.Id;
            await _db.SaveChangesAsync();
        }

        PaymentCallbackViewModel vm = new PaymentCallbackViewModel
        {
            Trx = trx,
            TrxCode = trxCode,
            ResultCode = resultCode,
            ResultMessage = resultMessage,
            Verified = verified,
            LocalExpectedHash = localExpected,
            ApiVerified = apiVerified,
            ApiExpectedHash = apiExpected,
            OrderId = orderId
        };
        return View(vm);
    }

    private DealerPaymentInputModel BuildNewModel()
    {
        DealerPaymentInputModel model = new DealerPaymentInputModel();
        PopulateLists(model);
        return model;
    }

    private void PopulateLists(DealerPaymentInputModel model)
    {
        model.ExpireMonths = Enumerable.Range(1, 12)
            .Select(i => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Value = i.ToString("00"), Text = i.ToString("00") })
            .ToList();
        int year = DateTime.UtcNow.Year;
        model.ExpireYears = Enumerable.Range(0, 15)
            .Select(i => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Value = (year + i).ToString(), Text = (year + i).ToString() })
            .ToList();
    }

    private static string Sha256(string input)
    {
        using SHA256 sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    }

    private static string Compute3DHash(string dealerCode, string otherTrxCode, string codeForHash, string password)
    {
        string raw = dealerCode + otherTrxCode + codeForHash + password;
        return Sha256(raw);
    }

    private static string MaskCard(string number)
    {
        if (string.IsNullOrWhiteSpace(number) || number.Length < 8) return "****";
        return number.Substring(0, 6) + new string('*', Math.Max(0, number.Length - 10)) + number[^4..];
    }
}
