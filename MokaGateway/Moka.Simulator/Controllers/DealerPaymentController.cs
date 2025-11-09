using Microsoft.AspNetCore.Mvc;
using Moka.Contracts.Payments;
using Moka.Contracts.Settings;
using Moka.Simulator.Models;
using Moka.Simulator.Services;
using System.Net.Http;
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
    private readonly Data.SimulatorDbContext _db;

    public DealerPaymentController(
    IConfiguration config,
    ILogger<DealerPaymentController> logger,
    IHttpClientFactory httpClientFactory,
    Microsoft.Extensions.Options.IOptions<MokaSettings> settings,
    Data.SimulatorDbContext db,
    IOrderService orders)
    {
        _config = config;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _settings = settings.Value;
        _db = db;
        _orders = orders;
    }

    [HttpGet]
    public IActionResult Create()
    {
        var model = BuildNewModel();
        model.TestCards = GetTestCards();
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(DealerPaymentInputModel model)
    {
        if (!ModelState.IsValid)
        {
            PopulateLists(model);
            model.TestCards = GetTestCards();
            return View(model);
        }
        var mode = _settings.Mode ?? _config["Moka:Mode"] ?? "Test";
        var dealerCode = _settings.DealerCode ?? "DEALER";
        var username = _settings.Username ?? "apiuser";
        var password = _settings.Password ?? "apipass";
        var postUrl = _settings.PostUrl ?? _config["Moka:PostUrl"];
        var redirectUrl = _settings.RedirectUrl ?? _config["Moka:RedirectUrl"];
        if (string.IsNullOrWhiteSpace(postUrl))
        {
            ModelState.AddModelError(string.Empty, "PostUrl is not configured.");
            PopulateLists(model);
            model.TestCards = GetTestCards();
            return View(model);
        }
        var now = DateTime.UtcNow;
        var otherTrxCode = $"VN{now:ddMMyyyyHHmmssfff}";
        var cardNumber = (model.CardNumber ?? string.Empty).Replace(" ", string.Empty);
        var clientIp = mode.Equals("Test", StringComparison.OrdinalIgnoreCase) ? "127.0.0.1" : HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
        var request = new DealerPaymentServicePaymentRequest
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
        var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = null };
        try
        {
            var client = _httpClientFactory.CreateClient();
            using var msg = new HttpRequestMessage(HttpMethod.Post, postUrl);
            msg.Content = new StringContent(JsonSerializer.Serialize(request, jsonOptions), Encoding.UTF8, "application/json");
            if (postUrl.Contains("localhost", StringComparison.OrdinalIgnoreCase))
                msg.Headers.Add("X-API-KEY", _config["ApiKeys:Primary"] ?? "dev-key");
            using var response = await client.SendAsync(msg);
            if (!response.IsSuccessStatusCode)
            {
                ModelState.AddModelError(string.Empty, $"Gateway error: {(int)response.StatusCode} {response.ReasonPhrase}");
                PopulateLists(model);
                model.TestCards = GetTestCards();
                return View(model);
            }
            var responseJson = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<DealerPaymentServicePaymentResult>(responseJson, jsonOptions) ?? new DealerPaymentServicePaymentResult();
            foreach (var warning in result.Warnings) ModelState.AddModelError(string.Empty, warning);
            if (string.Equals(result.ResultCode, "Success", StringComparison.OrdinalIgnoreCase) && result.Data?.Url is string url && !string.IsNullOrWhiteSpace(url))
            {
                _db.PaymentSessions.Add(new Data.PaymentSession { OtherTrxCode = otherTrxCode, CodeForHash = result.Data.CodeForHash ?? string.Empty, Amount = model.Amount, Currency = "TL", MaskedCard = MaskCard(cardNumber) });
                await _db.SaveChangesAsync();
                var simulatedHash = Compute3DHash(dealerCode, otherTrxCode, result.Data.CodeForHash ?? string.Empty, password);
                model.PostUrl = url;
                model.Trx = otherTrxCode;
                model.Hash = simulatedHash;
                return View("GatewayRedirect", model);
            }
            if (!string.IsNullOrWhiteSpace(result.ResultCode)) ModelState.AddModelError(string.Empty, GetCardResultMessage(result.ResultCode));
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
        model.TestCards = GetTestCards();
        return View(model);
    }

    [HttpGet, HttpPost]
    public async Task<IActionResult> Callback(string? trx, string? resultCode = null, string? resultMessage = null, string? hash = null)
    {
        // Gather values (POST fields priority)
        var form = Request.HasFormContentType ? Request.Form : null;
        var hashValue = form?["hashValue"].FirstOrDefault();
        var trxCode = form?["trxCode"].FirstOrDefault();
        var otherTrx = form?["OtherTrxCode"].FirstOrDefault();
        trx ??= otherTrx ?? Request.Query["trx"].FirstOrDefault();
        hash ??= hashValue ?? Request.Query["hash"].FirstOrDefault();
        resultCode ??= form?["resultCode"].FirstOrDefault() ?? Request.Query["resultCode"].FirstOrDefault();
        resultMessage ??= form?["resultMessage"].FirstOrDefault() ?? Request.Query["resultMessage"].FirstOrDefault();

        // Load session from DB
        Data.PaymentSession? session = null;
        if (!string.IsNullOrWhiteSpace(trx))
            session = _db.PaymentSessions.FirstOrDefault(s => s.OtherTrxCode == trx);

        bool verified = false;
        string localExpected = string.Empty;
        if (session != null && !string.IsNullOrWhiteSpace(hash))
        {
            var dealerCode = _settings.DealerCode ?? string.Empty;
            var password = _settings.Password ?? string.Empty;
            localExpected = Compute3DHash(dealerCode, trx!, session.CodeForHash, password);
            verified = string.Equals(localExpected, hash, StringComparison.OrdinalIgnoreCase);
        }

        // Remote verify via API (optional)
        bool apiVerified = false;
        string? apiExpected = null;
        if (session != null && !string.IsNullOrWhiteSpace(_settings.PostUrl) && !string.IsNullOrWhiteSpace(trx) && !string.IsNullOrWhiteSpace(hash))
        {
            try
            {
                var verifyUrl = _settings.PostUrl!.EndsWith("/pay", StringComparison.OrdinalIgnoreCase)
                ? _settings.PostUrl[..^3] + "verify3d"
                : _settings.PostUrl!.Replace("pay", "verify3d");
                var dict = new Dictionary<string, string>
 {
 {"trx", trx!},
 {"hash", hash!},
 {"dealerCode", _settings.DealerCode ?? string.Empty},
 {"codeForHash", session!.CodeForHash}
 };
                var client = _httpClientFactory.CreateClient();
                using var resp = await client.PostAsync(verifyUrl, new FormUrlEncodedContent(dict));
                if (resp.IsSuccessStatusCode)
                {
                    var js = await resp.Content.ReadAsStringAsync();
                    using var doc = JsonDocument.Parse(js);
                    apiVerified = doc.RootElement.TryGetProperty("verified", out var v) && v.GetBoolean();
                    if (doc.RootElement.TryGetProperty("expected", out var exp)) apiExpected = exp.GetString();
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Remote verify failed for trx={trx}", trx);
            }
        }

        // Create order if verified; update session
        int? orderId = null;
        if (verified && session != null)
        {
            session.TrxCode = trxCode ?? session.TrxCode;
            var order = _orders.Create(trx!, session.TrxCode ?? string.Empty, session.Amount, session.Currency, session.MaskedCard);
            orderId = order.Id;
            await _db.SaveChangesAsync();
        }

        var vm = new PaymentCallbackViewModel
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
        var model = new DealerPaymentInputModel();
        PopulateLists(model);
        return model;
    }

    private void PopulateLists(DealerPaymentInputModel model)
    {
        model.ExpireMonths = Enumerable.Range(1, 12)
        .Select(i => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Value = i.ToString("00"), Text = i.ToString("00") })
        .ToList();
        var year = DateTime.UtcNow.Year;
        model.ExpireYears = Enumerable.Range(0, 15)
        .Select(i => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Value = (year + i).ToString(), Text = (year + i).ToString() })
        .ToList();
    }

    private static string Sha256(string input)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
    }

    private static string Compute3DHash(string dealerCode, string otherTrxCode, string codeForHash, string password)
    {
        var raw = dealerCode + otherTrxCode + codeForHash + password;
        return Sha256(raw);
    }

    private static string MaskCard(string number)
    {
        if (string.IsNullOrWhiteSpace(number) || number.Length < 8) return "****";
        return number.Substring(0, 6) + new string('*', Math.Max(0, number.Length - 10)) + number[^4..];
    }

    private static string GetCardResultMessage(string resultCode) => resultCode switch
    {
        "PaymentDealer.CheckPaymentDealerAuthentication.InvalidRequest" => "Geçersiz istek.",
        "PaymentDealer.CheckPaymentDealerAuthentication.InvalidAccount" => "Geçersiz hesap.",
        "PaymentDealer.CheckPaymentDealerAuthentication.VirtualPosNotFound" => "Sanal POS bulunamadý.",
        "PaymentDealer.CheckDealerPaymentLimits.DailyDealerLimitExceeded" => "Günlük bayi limiti aþýldý.",
        "PaymentDealer.CheckDealerPaymentLimits.DailyCardLimitExceeded" => "Günlük kart limiti aþýldý.",
        "PaymentDealer.CheckCardInfo.InvalidCardInfo" => "Kart bilgileri geçersiz.",
        "PaymentDealer.DoDirectPayment3dRequest.InvalidRequest" => "3D ödeme isteði geçersiz.",
        "PaymentDealer.DoDirectPayment3dRequest.RedirectUrlRequired" => "Yönlendirme adresi gerekli.",
        "PaymentDealer.DoDirectPayment3dRequest.InvalidCurrencyCode" => "Geçersiz para birimi.",
        "PaymentDealer.DoDirectPayment3dRequest.InvalidInstallmentNumber" => "Geçersiz taksit sayýsý.",
        "PaymentDealer.DoDirectPayment3dRequest.InstallmentNotAvailableForForeignCurrencyTransaction" => "Yabancý para iþlemlerinde taksit yok.",
        "PaymentDealer.DoDirectPayment3dRequest.ForeignCurrencyNotAvailableForThisDealer" => "Bayi için yabancý para geçersiz.",
        _ => "Ýþleminizi gerçekleþtiremiyoruz. Kredi kartý bilgilerinizi kontrol ettikten sonra tekrar deneyiniz."
    };

    private static List<TestCard> GetTestCards()
    {
        var cards = new List<TestCard>();
        void Add(string brand, string number, string mmyy, string cvc)
        {
            if (mmyy.Length == 4)
            {
                var mm = mmyy[..2];
                var yy = mmyy[2..];
                cards.Add(new TestCard { Brand = brand, Number = number, Holder = brand, ExpMonth = mm, ExpYear = $"20{yy}", Cvc = cvc });
            }
        }
        // Listed cards (only these kept)
        Add("AMEXP", "375624000001036", "0426", "3041");
        Add("BNSCMP", "374427543211042", "0427", "454");
        Add("BONUS", "5406697543211173", "0427", "423");
        Add("BONUS", "5549603469426017", "0127", "916");
        Add("DEBITSNL", "5170414005187022", "1029", "705");
        Add("PARACARD", "9792364832690872", "1029", "579");
        Add("PARACARD", "5170404966123637", "0326", "096");
        Add("PARACARD", "4894554902175881", "0326", "616");
        Add("Simülatör", "4282209004348015", "0827", "123");
        Add("TROY", "9792052565200015", "0127", "327");
        Add("TROY", "9792052725569010", "0127", "113");
        Add("AMEXE", "375622673470017", "0826", "543");
        Add("BONUS", "5406697543211173", "0427", "423");
        Add("BONUS", "5549600797792011", "0827", "460");
        Add("BNSTK", "4273142532401017", "0627", "165");
        Add("BNSTK", "4273142794777013", "0627", "464");
        Add("BNSTK", "4273142247610019", "0627", "997");
        Add("BNSTK", "4273142351799012", "0627", "763");
        Add("BNSTK", "4273142754601013", "0627", "338");
        Add("PARACARD", "5170414656727753", "1129", "355");
        Add("SF", "4329544414118011", "1126", "123");
        Add("SF", "5378290673596011", "0927", "833");
        Add("SF", "5378290215128018", "0927", "013");
        Add("SF", "5378299769934010", "0927", "230");
        Add("SMTK", "5331692942307011", "0828", "784");
        Add("SM", "5289391576515013", "0827", "676");
        Add("SM", "5209880710012017", "0827", "176");
        Add("BNTTK", "9792290000022038", "0929", "094");
        Add("BNTCG", "9792290100021104", "0129", "001");
        Add("BNTCP", "9792290200001154", "1228", "064");
        Add("BNTTK", "9792290374126019", "0525", "198");
        Add("BNTCG", "9792290103612016", "0829", "570");
        Add("BNSTRY", "9792290527426019", "0829", "611");
        Add("BNSTRY", "9792290648763019", "0229", "543");
        Add("BNSSANAL", "9792290735587016", "0226", "790");
        Add("AMEX", "377599286520016", "0928", "4165");
        Add("AMEX", "377598136580014", "0926", "1269");
        Add("AMEX", "377597476200019", "0929", "6447");
        Add("SF", "5381211147620018", "0929", "369");
        Add("SF", "5499970713658012", "0926", "799");
        Add("SF", "5378290828652016", "0928", "444");
        return cards;
    }
}
