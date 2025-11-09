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
        string otherTrxCode = Guid.NewGuid().ToString("N");
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
            
            var httpLog = new Data.HttpLog
            {
                Direction = "Outbound",
                Url = postUrl,
                Method = "POST",
                RequestHeaders = string.Join("\n", msg.Headers.Select(h => h.Key+":"+string.Join(',',h.Value)) ),
                RequestBody = JsonSerializer.Serialize(request, jsonOptions)
            };
            _db.HttpLogs.Add(httpLog);
            await _db.SaveChangesAsync();

            using HttpResponseMessage response = await client.SendAsync(msg);
            
            httpLog.Direction = "Outbound"; // keep
            httpLog.StatusCode = (int)response.StatusCode;
            httpLog.ResponseHeaders = string.Join("\n", response.Headers.Select(h => h.Key+":"+string.Join(',',h.Value)) );
            string responseJson = await response.Content.ReadAsStringAsync();
            httpLog.ResponseBody = responseJson;
            await _db.SaveChangesAsync();
            
            if (!response.IsSuccessStatusCode)
            {
                ModelState.AddModelError(string.Empty, $"Gateway error: {(int)response.StatusCode} {response.ReasonPhrase}");
                PopulateLists(model);
                model.TestCards = _testData.GetTestCards();
                return View(model);
            }

            DealerPaymentServicePaymentResult result = JsonSerializer.Deserialize<DealerPaymentServicePaymentResult>(responseJson, jsonOptions) ?? new DealerPaymentServicePaymentResult();
            foreach (string warning in result.Warnings) ModelState.AddModelError(string.Empty, warning);
           
            if (string.Equals(result.ResultCode, "Success", StringComparison.OrdinalIgnoreCase) && result.Data?.Url is string url && !string.IsNullOrWhiteSpace(url))
            {
                _db.PaymentSessions.Add(new Data.PaymentSession { OtherTrxCode = otherTrxCode, CodeForHash = result.Data.CodeForHash ?? string.Empty, Amount = model.Amount, Currency = "TL", MaskedCard = MaskCard(cardNumber) });
                await _db.SaveChangesAsync();
                model.PostUrl = url;
                model.Trx = otherTrxCode;
                model.Hash = string.Empty;
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
        // Inbound HTTP log
        var inboundLog = new Data.HttpLog
        {
            Direction = "Inbound",
            Url = Request.Path + Request.QueryString,
            Method = Request.Method,
            RequestHeaders = string.Join("\n", Request.Headers.Select(h => h.Key+":"+string.Join(',',h.Value))) ,
            RequestBody = form != null ? string.Join("&", form.Keys.Select(k => $"{k}={form[k].ToString()}")) : string.Empty
        };
        _db.HttpLogs.Add(inboundLog);
        await _db.SaveChangesAsync();
 
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
            // ReturnHash: CodeForHash + (resultCode == Success ? T : F)
            string suffix = string.Equals(resultCode, "Success", StringComparison.OrdinalIgnoreCase) ? "T" : "F";
            using SHA256 sha = SHA256.Create();
            localExpected = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes((session.CodeForHash ?? string.Empty) + suffix))).ToLowerInvariant();
            verified = string.Equals(localExpected, hash, StringComparison.OrdinalIgnoreCase);
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
            ApiVerified = false,
            ApiExpectedHash = null,
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

    private static string MaskCard(string number)
    {
        if (string.IsNullOrWhiteSpace(number) || number.Length < 8) return "****";
        return number.Substring(0, 6) + new string('*', Math.Max(0, number.Length - 10)) + number[^4..];
    }
}
