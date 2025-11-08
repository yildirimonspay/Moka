using Microsoft.AspNetCore.Mvc;
using Moka.Contracts.Payments;
using Moka.Contracts.Settings;
using Moka.Simulator.Models;
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

    public DealerPaymentController(IConfiguration config, ILogger<DealerPaymentController> logger, IHttpClientFactory httpClientFactory, Microsoft.Extensions.Options.IOptions<MokaSettings> settings)
    {
        _config = config;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _settings = settings.Value;
    }

    [HttpGet]
    public IActionResult Create()
    {
        var model = BuildNewModel();
        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Create(DealerPaymentInputModel model)
    {
        if (!ModelState.IsValid)
        {
            PopulateLists(model);
            return View(model);
        }

        var mode = _settings.Mode ?? _config["Moka:Mode"] ?? "Test";
        var dealerCode = _settings.DealerCode ?? model.DealerCode;
        var username = _settings.Username ?? model.Username;
        var password = _settings.Password ?? model.Password;
        var postUrl = _settings.PostUrl ?? _config["Moka:PostUrl"];
        var redirectUrl = _settings.RedirectUrl ?? _config["Moka:RedirectUrl"] ?? model.RedirectUrl;

        if (string.IsNullOrWhiteSpace(postUrl))
        {
            ModelState.AddModelError(string.Empty, "PostUrl is not configured.");
            PopulateLists(model);
            return View(model);
        }

        var now = DateTime.UtcNow;
        var otherTrxCode = $"VN{now:ddMMyyyyHHmmssfff}";
        var cardNumber = (model.CardNumber ?? string.Empty).Replace(" ", string.Empty);
        var clientIp = mode.Equals("Test", StringComparison.OrdinalIgnoreCase) ? "127.0.0.1" : HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";

        var request = new DealerPaymentServicePaymentRequest
        {
            PaymentDealerAuthentication = new PaymentDealerAuthentication
            {
                DealerCode = dealerCode,
                Username = username,
                Password = password,
                CheckKey = Sha256((dealerCode ?? string.Empty) + "MK" + (username ?? string.Empty) + "PD" + (password ?? string.Empty))
            },
            PaymentDealerRequest = new PaymentDealerRequest
            {
                CardHolderFullName = model.CardHolderFullName,
                CardNumber = cardNumber,
                ExpMonth = model.ExpMonth,
                ExpYear = model.ExpYear,
                CvcNumber = model.CvcNumber,
                Amount = model.Amount,
                Currency = string.IsNullOrWhiteSpace(model.Currency) ? "TL" : model.Currency!,
                InstallmentNumber = model.InstallmentNumber <=0 ?1 : model.InstallmentNumber,
                VirtualPosOrderId = model.VirtualPosOrderId,
                OtherTrxCode = otherTrxCode,
                VoidRefundReason = model.VoidRefundReason,
                ClientIP = clientIp,
                RedirectUrl = redirectUrl,
                ReturnHash =1
            }
        };

        var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = null };
        try
        {
            var client = _httpClientFactory.CreateClient();
            using var content = new StringContent(JsonSerializer.Serialize(request, jsonOptions), Encoding.UTF8, "application/json");
            using var response = await client.PostAsync(postUrl, content);
            if (!response.IsSuccessStatusCode)
            {
                ModelState.AddModelError(string.Empty, $"Gateway error: {(int)response.StatusCode} {response.ReasonPhrase}");
                PopulateLists(model);
                return View(model);
            }
            var responseJson = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<DealerPaymentServicePaymentResult>(responseJson, jsonOptions) ?? new DealerPaymentServicePaymentResult();
            foreach (var warning in result.Warnings) ModelState.AddModelError(string.Empty, warning);
            if (string.Equals(result.ResultCode, "Success", StringComparison.OrdinalIgnoreCase) && result.Data?.Url is string url && !string.IsNullOrWhiteSpace(url))
            {
                return Redirect(url);
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
        return View(model);
    }

    private DealerPaymentInputModel BuildNewModel()
    {
        var model = new DealerPaymentInputModel();
        PopulateLists(model);
        model.Currency = _settings.Mode == "Test" ? "TRY" : (model.Currency ?? "TRY");
        model.RedirectUrl = _settings.RedirectUrl ?? _config["Moka:RedirectUrl"];
        return model;
    }

    private void PopulateLists(DealerPaymentInputModel model)
    {
        model.ExpireMonths = Enumerable.Range(1,12).Select(i => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Value = i.ToString("00"), Text = i.ToString("00") }).ToList();
        var year = DateTime.UtcNow.Year;
        model.ExpireYears = Enumerable.Range(0,15).Select(i => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Value = (year + i).ToString(), Text = (year + i).ToString() }).ToList();
    }

    private static string Sha256(string input)
    {
        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(input))).ToLowerInvariant();
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
        "PaymentDealer.DoDirectPayment3dRequest.PaymentMustBeAuthorization" => "Ödeme provizyon olmalý.",
        "PaymentDealer.DoDirectPayment3dRequest.AuthorizationForbiddenForThisDealer" => "Provizyon yasaklý.",
        "PaymentDealer.DoDirectPayment3dRequest.PoolPaymentNotAvailableForDealer" => "Havuz ödeme uygun deðil.",
        "PaymentDealer.DoDirectPayment3dRequest.PoolPaymentRequiredForDealer" => "Havuz ödeme gerekli.",
        "PaymentDealer.DoDirectPayment3dRequest.TokenizationNotAvailableForDealer" => "Tokenizasyon uygun deðil.",
        "PaymentDealer.DoDirectPayment3dRequest.CardTokenCannotUseWithSaveCard" => "Kart token, kaydet ile kullanýlamaz.",
        "PaymentDealer.DoDirectPayment3dRequest.CardTokenNotFound" => "Kart token bulunamadý.",
        "PaymentDealer.DoDirectPayment3dRequest.OnlyCardTokenOrCardNumber" => "Sadece kart token veya kart numarasý kullanýlmalý.",
        "PaymentDealer.DoDirectPayment3dRequest.ChannelPermissionNotAvailable" => "Kanal izni yok.",
        "PaymentDealer.DoDirectPayment3dRequest.IpAddressNotAllowed" => "IP adresine izin yok.",
        "PaymentDealer.DoDirectPayment3dRequest.VirtualPosNotAvailable" => "Sanal POS uygun deðil.",
        "PaymentDealer.DoDirectPayment3dRequest.ThisInstallmentNumberNotAvailableForVirtualPos" => "Taksit sayýsý bu POS için uygun deðil.",
        "PaymentDealer.DoDirectPayment3dRequest.ThisInstallmentNumberNotAvailableForDealer" => "Taksit sayýsý bayi için uygun deðil.",
        "PaymentDealer.DoDirectPayment3dRequest.DealerCommissionRateNotFound" => "Komisyon oraný bulunamadý.",
        "PaymentDealer.DoDirectPayment3dRequest.DealerGroupCommissionRateNotFound" => "Grup komisyon oraný bulunamadý.",
        "PaymentDealer.DoDirectPayment3dRequest.InvalidSubMerchantName" => "Geçersiz alt üye iþyeri adý.",
        "PaymentDealer.DoDirectPayment3dRequest.InvalidUnitPrice" => "Geçersiz birim fiyat.",
        "PaymentDealer.DoDirectPayment3dRequest.InvalidQuantityValue" => "Geçersiz adet.",
        "PaymentDealer.DoDirectPayment3dRequest.BasketAmountIsNotEqualPaymentAmount" => "Sepet ve ödeme tutarý eþit deðil.",
        "PaymentDealer.DoDirectPayment3dRequest.BasketProductNotFoundInYourProductList" => "Sepet ürünü tanýmlý deðil.",
        "PaymentDealer.DoDirectPayment3dRequest.MustBeOneOfDealerProductIdOrProductCode" => "Ürün kimliði ya da kodu gerekli.",
        _ => "Ýþleminizi gerçekleþtiremiyoruz. Kredi kartý bilgilerinizi kontrol ettikten sonra tekrar deneyiniz."
    };
}
