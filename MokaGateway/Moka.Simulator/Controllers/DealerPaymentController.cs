using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
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
            ModelState.AddModelError(string.Empty, "PostUrl yapılandırılmadı.");
            PopulateLists(model);
            model.TestCards = _testData.GetTestCards();
            return View(model);
        }

        DateTime now = DateTime.UtcNow;
        string otherTrxCode = Guid.NewGuid().ToString("N");
        string cardNumber = (model.CardNumber ?? string.Empty).Replace(" ", string.Empty);
        string clientIp = mode.Equals("Test", StringComparison.OrdinalIgnoreCase) ? "127.0.0.1" : HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;

        // Generate merchant-side nonce and include in RedirectUrl as mnonce query param (server will preserve it)
        string merchantNonce = Guid.NewGuid().ToString("N");
        string? redirectUrlWithNonce = AppendQueryParam(redirectUrl, "mnonce", merchantNonce);

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
                RedirectUrl = redirectUrlWithNonce,
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
            
            // Sanitize request body and headers for logging
            var sanitizedRequest = new DealerPaymentServicePaymentRequest
            {
                PaymentDealerAuthentication = request.PaymentDealerAuthentication, // no secret here beyond password which isn't logged
                PaymentDealerRequest = new PaymentDealerRequest
                {
                    CardHolderFullName = request.PaymentDealerRequest.CardHolderFullName,
                    CardNumber = MaskCard(cardNumber),
                    ExpMonth = request.PaymentDealerRequest.ExpMonth,
                    ExpYear = request.PaymentDealerRequest.ExpYear,
                    CvcNumber = null, // never log CVC
                    Amount = request.PaymentDealerRequest.Amount,
                    Currency = request.PaymentDealerRequest.Currency,
                    InstallmentNumber = request.PaymentDealerRequest.InstallmentNumber,
                    OtherTrxCode = request.PaymentDealerRequest.OtherTrxCode,
                    ClientIP = request.PaymentDealerRequest.ClientIP,
                    RedirectUrl = request.PaymentDealerRequest.RedirectUrl,
                    ReturnHash = request.PaymentDealerRequest.ReturnHash
                }
            };
            var requestJsonForLog = JsonSerializer.Serialize(sanitizedRequest, jsonOptions);
            var headersForLog = SanitizeHeaders(msg.Headers).ToList();

            var httpLog = new Data.HttpLog
            {
                Direction = "Outbound",
                Url = postUrl,
                Method = "POST",
                RequestHeaders = string.Join("\n", headersForLog.Select(h => h.Key + ":" + string.Join(',', h.Value))),
                RequestBody = requestJsonForLog
            };
            _db.HttpLogs.Add(httpLog);
            await _db.SaveChangesAsync();

            using HttpResponseMessage response = await client.SendAsync(msg);
            
            httpLog.Direction = "Outbound"; // keep
            httpLog.StatusCode = (int)response.StatusCode;
            httpLog.ResponseHeaders = string.Join("\n", SanitizeHeaders(response.Headers).Select(h => h.Key + ":" + string.Join(',', h.Value)));
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
                // Persist session with server-side expected nonce to validate later
                _db.PaymentSessions.Add(new Data.PaymentSession { OtherTrxCode = otherTrxCode, CodeForHash = result.Data.CodeForHash ?? string.Empty, Amount = model.Amount, Currency = "TL", MaskedCard = MaskCard(cardNumber), MerchantNonce = merchantNonce });
                await _db.SaveChangesAsync();
                model.PostUrl = url;
                model.Trx = otherTrxCode;
                model.Hash = string.Empty;
                return View("GatewayRedirect", model);
            }
            // If we got a non-success code, prepare auto POST to Callback so UI shows unified result
            if (!string.IsNullOrWhiteSpace(result.ResultCode) && !string.Equals(result.ResultCode, "Success", StringComparison.OrdinalIgnoreCase))
            {
                ViewBag.ResultCode = result.ResultCode;
                ViewBag.ResultMessage = result.ResultMessage ?? _testData.GetErrorMessage(result.ResultCode);
                model.Trx = otherTrxCode;
                model.Hash = string.Empty; // hash unknown since bank not reached
                return View("GatewayPost", model);
            }

            if (!string.IsNullOrWhiteSpace(result.ResultCode)) ModelState.AddModelError(string.Empty, _testData.GetErrorMessage(result.ResultCode));
            if (!string.IsNullOrWhiteSpace(result.ResultMessage)) ModelState.AddModelError(string.Empty, result.ResultMessage);
        }
        catch (TaskCanceledException)
        {
            ModelState.AddModelError(string.Empty, "İstek zaman aşımına uğradı.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Payment request failed");
            ModelState.AddModelError(string.Empty, "Beklenmeyen bir hata oluştu.");
        }

        PopulateLists(model);
        model.TestCards = _testData.GetTestCards();
        return View(model);
    }

    [EnableRateLimiting("gateway")]
    [HttpPost]
    [Consumes("application/x-www-form-urlencoded")]
    [RequestSizeLimit(16 *1024)]
    [RequestFormLimits(ValueLengthLimit =2048, ValueCountLimit =64, KeyLengthLimit =256)]
    public async Task<IActionResult> Callback([FromForm] Moka.Contracts.Payments.CallbackDto dto)
    {
        IFormCollection? form = Request.HasFormContentType ? Request.Form : null;
        // Inbound HTTP log (sanitize headers)
        var inboundLog = new Data.HttpLog
        {
            Direction = "Inbound",
            Url = Request.Path + Request.QueryString,
            Method = Request.Method,
            RequestHeaders = string.Join("\n", SanitizeHeaders(Request.Headers).Select(h => h.Key + ":" + string.Join(',', h.Value))),
            RequestBody = form != null ? string.Join("&", form.Keys.Select(k => $"{k}={form[k].ToString()}")) : string.Empty
        };
        _db.HttpLogs.Add(inboundLog);
        await _db.SaveChangesAsync();
        
        string? trx = dto.OtherTrxCode ?? dto.trx;
        string? hash = dto.hashValue;
        string? trxCode = dto.trxCode;
        string? authorizationCode = dto.authorizationCode;
        string? resultCode = dto.resultCode;
        string? resultMessage = dto.resultMessage;
        string? nonce = dto.nonce; // PSP-provided nonce
        string? merchantNonce = Request.Query["mnonce"].FirstOrDefault(); // merchant-provided expected nonce

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
            // constant-time compare for hash as well
            verified = SignaturesEqual(localExpected, hash);
        }

        // nonce validation: compare only with stored value, never overwrite. Also reject replays.
        bool nonceOk = !string.IsNullOrEmpty(session?.MerchantNonce) && string.Equals(session!.MerchantNonce, merchantNonce, StringComparison.Ordinal);
        bool notReplayed = session?.NonceUsed != true;
        verified = verified && nonceOk && notReplayed;

        int? orderId = null;
        if (verified && session != null)
        {
            session.TrxCode = authorizationCode ?? trxCode ?? session.TrxCode;
            session.NonceUsed = true;
            session.NonceUsedUtc = DateTime.UtcNow;
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

        string? signature = dto.signature;
        if (!string.IsNullOrWhiteSpace(signature))
        {
            // Build payload in the same order as API to verify signature
            var expectedSigPayload = BuildApiSignaturePayload(trxCode, dto.OtherTrxCode ?? trx, resultCode, hash, nonce);
            var secret = _settings.RedirectHmacSecret;
            string expectedSig = string.Empty;
            if (!string.IsNullOrWhiteSpace(secret))
            {
                using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
                expectedSig = Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(expectedSigPayload))).ToLowerInvariant();
            }
            if (!string.IsNullOrWhiteSpace(expectedSig) && SignaturesEqual(expectedSig, signature))
            {
                vm.ApiVerified = true;
                vm.ApiExpectedHash = expectedSig;
            }
        }

        return View(vm);
    }

    private static string BuildApiSignaturePayload(string? trxCode, string? otherTrx, string? resultCode, string? hashValue, string? nonce)
    {
        // Match API order exactly: trxCode, OtherTrxCode, resultCode, hashValue, nonce
        return $"trxCode={trxCode}&OtherTrxCode={otherTrx}&resultCode={resultCode}&hashValue={hashValue}&nonce={nonce}";
    }

    private static bool SignaturesEqual(string? a, string? b)
    {
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
        try
        {
            var ba = Convert.FromHexString(a);
            var bb = Convert.FromHexString(b);
            return CryptographicOperations.FixedTimeEquals(ba, bb);
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<KeyValuePair<string, IEnumerable<string>>> SanitizeHeaders(IHeaderDictionary headers)
    {
        foreach (var kv in headers)
        {
            var key = kv.Key;
            if (key.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("X-API-KEY", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Api-Key", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("X-Api-Key", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
            {
                yield return new KeyValuePair<string, IEnumerable<string>>(key, new[] { "***" });
            }
            else
            {
                yield return new KeyValuePair<string, IEnumerable<string>>(key, kv.Value.AsEnumerable());
            }
        }
    }
    // overload for request/response header collections
    private static IEnumerable<KeyValuePair<string, IEnumerable<string>>> SanitizeHeaders(System.Net.Http.Headers.HttpHeaders headers)
    {
        foreach (var kv in headers)
        {
            var key = kv.Key;
            if (key.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("X-API-KEY", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Api-Key", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("X-Api-Key", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
            {
                yield return new KeyValuePair<string, IEnumerable<string>>(key, new[] { "***" });
            }
            else
            {
                yield return kv;
            }
        }
    }

    private static string AppendQueryParam(string? url, string key, string value)
    {
        if (string.IsNullOrWhiteSpace(url)) return url ?? string.Empty;
        var separator = url.Contains('?') ? '&' : '?';
        return url + separator + Uri.EscapeDataString(key) + "=" + Uri.EscapeDataString(value);
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
        if (string.IsNullOrWhiteSpace(number)) return "****";
        var digits = new string(number.Where(char.IsDigit).ToArray());
        if (digits.Length < 8) return "****";
        return digits.Substring(0, 6) + new string('*', Math.Max(0, digits.Length - 10)) + digits[^4..];
    }
}
