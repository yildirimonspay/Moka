using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using Moka.Contracts.Payments;
using Moka.Contracts.Settings;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using Swashbuckle.AspNetCore.Filters;
using System.Text;
using System.ComponentModel.DataAnnotations;

namespace Moka.Api.Controllers;

[ApiController]
[Route("PaymentDealer")] // spec base route
public class MokaController : ControllerBase
{
    private readonly ILogger<MokaController> _logger;
    private readonly MokaSettings _settings;
    private readonly Data.MokaDbContext _db;

    public MokaController(ILogger<MokaController> logger, IOptions<MokaSettings> settings, Data.MokaDbContext db)
    {
        _logger = logger;
        _settings = settings.Value;
        _db = db;
    }

    [HttpPost("DoDirectPaymentThreeD")]
    [SwaggerRequestExample(typeof(DealerPaymentServicePaymentRequest), typeof(Moka.Api.Swagger.DealerPaymentExample))]
    public async Task<ActionResult<DealerPaymentServicePaymentResult>> Pay([FromBody] DealerPaymentServicePaymentRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(new DealerPaymentServicePaymentResult
            {
                ResultCode = "InvalidRequest",
                ResultMessage = "Validation failed",
                Warnings = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList()
            });
        }

        var auth = request.PaymentDealerAuthentication;
        if (auth is null)
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.CheckPaymentDealerAuthentication.InvalidRequest", ResultMessage = "Missing auth" });

        // Validate account against configured settings (simple demo check)
        if (!string.Equals(auth.DealerCode, _settings.DealerCode, StringComparison.Ordinal)
            || !string.Equals(auth.Username, _settings.Username, StringComparison.Ordinal)
            || !string.Equals(auth.Password, _settings.Password, StringComparison.Ordinal))
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.CheckPaymentDealerAuthentication.InvalidAccount", ResultMessage = "Invalid dealer credentials" });
        }

        // Validate CheckKey by spec: SHA256(DealerCode+"MK"+Username+"PD"+Password)
        string raw = (auth.DealerCode ?? string.Empty) + "MK" + (auth.Username ?? string.Empty) + "PD" + (auth.Password ?? string.Empty);
        using SHA256 sha = SHA256.Create();
        string expectedKey = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(auth.CheckKey) || !string.Equals(auth.CheckKey, expectedKey, StringComparison.OrdinalIgnoreCase))
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.CheckPaymentDealerAuthentication.InvalidRequest", ResultMessage = "Invalid CheckKey" });
        }

        // mask card and log
        var maskedCard = request.PaymentDealerRequest?.CardNumber;
        if (!string.IsNullOrWhiteSpace(maskedCard))
        {
            var digits = new string(maskedCard.Where(char.IsDigit).ToArray());
            if (digits.Length >=10) maskedCard = digits.Substring(0,6) + new string('*', digits.Length-10) + digits[^4..];
        }
        _logger.LogInformation("3D request Amount={amt} Currency={cur} MaskedCard={mc}", request.PaymentDealerRequest?.Amount, request.PaymentDealerRequest?.Currency, maskedCard);

        try
        {
            var req = request.PaymentDealerRequest;
            // RedirectUrl required
            if (string.IsNullOrWhiteSpace(req.RedirectUrl))
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.RedirectUrlRequired", ResultMessage = "RedirectUrl required", Data = null });
            // Currency whitelist
            var allowed = new[] { "TL", "USD", "EUR", "GBP", null, "" };
            if (!allowed.Contains(req.Currency))
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.InvalidCurrencyCode", ResultMessage = "Invalid currency", Data = null });
            // Installment rules
            if (req.InstallmentNumber <0 || req.InstallmentNumber >12)
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.InvalidInstallmentNumber", ResultMessage = "Invalid installment", Data = null });
            // Card vs Token exclusivity
            if (string.IsNullOrWhiteSpace(req.CardNumber) && string.IsNullOrWhiteSpace(req.CardToken))
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.OnlyCardTokenOrCardNumber", ResultMessage = "Provide card or token", Data = null });
            if (!string.IsNullOrWhiteSpace(req.CardNumber) && !string.IsNullOrWhiteSpace(req.CardToken))
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.OnlyCardTokenOrCardNumber", ResultMessage = "Provide only one of card or token", Data = null });
            // ReturnHash must be1
            if (req.ReturnHash !=1)
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.InvalidRequest", ResultMessage = "ReturnHash must be1", Data = null });
        }
        catch (Exception ex)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "EX", ResultMessage = ex.Message, Exception = ex.ToString(), Data = null });
        }

        // IP whitelist (optional)
        if (_settings.AllowedIps != null && _settings.AllowedIps.Length >0)
        {
            var clientIp = request.PaymentDealerRequest.ClientIP ?? string.Empty;
            if (!_settings.AllowedIps.Contains(clientIp))
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.IpAddressNotAllowed", ResultMessage = "IP not allowed", Data = null });
        }

        var s = _settings;
        var reqPay = request.PaymentDealerRequest;
        // Tokenization permissions
        if (!string.IsNullOrWhiteSpace(reqPay.CardToken) && s.AllowTokenization == false)
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.TokenizationNotAvailableForDealer", ResultMessage = "Tokenization not allowed", Data = null });
        if (reqPay.IsTokenized ==1 && s.AllowTokenization == false)
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.TokenizationNotAvailableForDealer", ResultMessage = "Tokenization not allowed", Data = null });
        if (reqPay.IsTokenized ==1 && !string.IsNullOrWhiteSpace(reqPay.CardToken))
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.CardTokenCannotUseWithSaveCard", ResultMessage = "Cannot use token and save card", Data = null });
        if (!string.IsNullOrWhiteSpace(reqPay.CardToken) && !string.IsNullOrWhiteSpace(reqPay.CardNumber))
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.OnlyCardTokenOrCardNumber", ResultMessage = "Only card token or card number allowed", Data = null });

        // Pool payment permissions
        if (reqPay.IsPoolPayment ==1 && s.AllowPoolPayments == false)
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.PoolPaymentNotAvailableForDealer", ResultMessage = "Pool payment not allowed", Data = null });
        if (reqPay.IsPoolPayment ==0 && s.ForcePoolPayments)
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.PoolPaymentRequiredForDealer", ResultMessage = "Pool payment required", Data = null });

        // PreAuth permissions
        if (reqPay.IsPreAuth ==1 && s.AllowPreAuth == false)
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.AuthorizationForbiddenForThisDealer", ResultMessage = "PreAuth forbidden", Data = null });
        if (reqPay.IsPreAuth ==0 && s.AllowPreAuth && reqPay.IsPoolPayment ==0 && reqPay.InstallmentNumber>1)
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.PaymentMustBeAuthorization", ResultMessage = "Payment must be authorization for installments", Data = null });

        // Installment foreign currency restriction
        if (!string.IsNullOrWhiteSpace(reqPay.Currency) && reqPay.Currency != "TL" && reqPay.InstallmentNumber>1)
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.InstallmentNotAvailableForForeignCurrencyTransaction", ResultMessage = "No installments for foreign currency", Data = null });
        if (!string.IsNullOrWhiteSpace(reqPay.Currency) && s.ForeignCurrenciesEnabled != null && !s.ForeignCurrenciesEnabled.Contains(reqPay.Currency) && reqPay.Currency != "TL")
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.ForeignCurrencyNotAvailableForThisDealer", ResultMessage = "Foreign currency not allowed", Data = null });

        // SubMerchant name validation
        if (!string.IsNullOrWhiteSpace(reqPay.Description) && s.AllowedSubMerchants != null && reqPay.Description != null && !s.AllowedSubMerchants.Contains(reqPay.Description))
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.InvalidSubMerchantName", ResultMessage = "Invalid sub merchant", Data = null });

        // Software validation
        if (!string.IsNullOrWhiteSpace(reqPay.Software) && s.AllowedSoftware != null && !s.AllowedSoftware.Contains(reqPay.Software))
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.ChannelPermissionNotAvailable", ResultMessage = "Software/channel not permitted", Data = null });

        // Product basket validation for known codes
        if (reqPay.BasketProducts != null && reqPay.BasketProducts.Count>0 && s.KnownProductCodes != null)
        {
            foreach (var bp in reqPay.BasketProducts)
            {
                if (!string.IsNullOrWhiteSpace(bp.ProductCode) && !s.KnownProductCodes.Contains(bp.ProductCode))
                    return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.BasketProductNotFoundInYourProductList", ResultMessage = "Unknown product", Data = null });
                if (string.IsNullOrWhiteSpace(bp.ProductCode) && bp.ProductId==0)
                    return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.MustBeOneOfDealerProductIdOrProductCode", ResultMessage = "Need product id or code", Data = null });
            }
        }

        // Run data annotation validations explicitly for complex codes
        var ctx = new ValidationContext(request.PaymentDealerRequest);
        var results = new List<ValidationResult>();
        if (!Validator.TryValidateObject(request.PaymentDealerRequest, ctx, results, true))
        {
            var first = results.FirstOrDefault();
            if (first != null)
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = first.ErrorMessage, ResultMessage = string.Empty, Data = null });
        }

        // generate nonce and append to redirect url
        string otherTrx = request.PaymentDealerRequest.OtherTrxCode ?? Guid.NewGuid().ToString("N");
        string codeForHash = Guid.NewGuid().ToString().ToUpperInvariant();
        string nonce = Guid.NewGuid().ToString("N");
        string redirectUrl = request.PaymentDealerRequest.RedirectUrl ?? _settings.RedirectUrl ?? "https://example.com/return";
        if (!redirectUrl.Contains("?")) redirectUrl += "?nonce=" + Uri.EscapeDataString(nonce);
        else redirectUrl += "&nonce=" + Uri.EscapeDataString(nonce);
        string trxCode = $"ORDER-{otherTrx}"; // simulate order id from bank
        string threeDTrxCode = Guid.NewGuid().ToString("N");

        var entity = new Data.PaymentEntity
        {
            OtherTrxCode = otherTrx,
            TrxCode = trxCode,
            CodeForHash = codeForHash,
            ThreeDTrxCode = threeDTrxCode,
            RedirectUrl = redirectUrl,
            Nonce = nonce,
            Amount = request.PaymentDealerRequest.Amount,
            Currency = request.PaymentDealerRequest.Currency ?? "TL",
            Status = "Pending3D",
            CreatedUtc = DateTime.UtcNow
        };
        _db.Payments.Add(entity);
        await _db.SaveChangesAsync();
        _logger.LogInformation("Stored payment otherTrx={otherTrx} trxCode={trxCode} amount={amount}", otherTrx, trxCode, request.PaymentDealerRequest.Amount);

        // Return a bank-like3D page URL that will post back to merchant redirectUrl
        string baseUrl = $"{Request.Scheme}://{Request.Host}";
        string threeDUrl = $"{baseUrl}/PaymentDealer/PaymentDealerThreeDProcess?threeDTrxCode={Uri.EscapeDataString(threeDTrxCode)}";

        return Ok(new DealerPaymentServicePaymentResult
        {
            ResultCode = "Success",
            Data = new MokaData
            {
                Url = threeDUrl,
                CodeForHash = codeForHash
            }
        });
    }

    [HttpGet("PaymentDealerThreeDProcess")]
    public async Task<IActionResult> ThreeD([FromQuery] string threeDTrxCode)
    {
        var entity = await _db.Payments.FirstOrDefaultAsync(p => p.ThreeDTrxCode == threeDTrxCode);
        if (entity == null) return NotFound("Transaction not found");
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>3D Secure Kod</title></head><body>");
        sb.Append("<h3>3D Güvenlik Doðrulamasý</h3><p>Telefonunuza gelen4 haneli kodu giriniz (demo:1234).</p>");
        sb.Append("<form method='post' action='/PaymentDealer/PaymentDealerThreeDProcess'>");
        sb.Append("<input type='hidden' name='threeDTrxCode' value='").Append(System.Net.WebUtility.HtmlEncode(threeDTrxCode)).Append("' />");
        sb.Append("<input name='code' maxlength='4' autofocus pattern='[0-9]{4}' required />");
        sb.Append("<button type='submit'>Doðrula</button></form></body></html>");
        return Content(sb.ToString(), "text/html", Encoding.UTF8);
    }

    [HttpPost("PaymentDealerThreeDProcess")]
    public async Task<IActionResult> ThreeDSubmit([FromForm] string threeDTrxCode, [FromForm] string code)
    {
        var entity = await _db.Payments.FirstOrDefaultAsync(p => p.ThreeDTrxCode == threeDTrxCode);
        if (entity == null) return NotFound("Transaction not found");
        bool success = code == "1234";
        // ReturnHash rule: CodeForHash + T/F -> SHA256
        string suffix = success ? "T" : "F";
        using SHA256 sha = SHA256.Create();
        string hashValue = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(entity.CodeForHash + suffix))).ToLowerInvariant();
        entity.Status = success ? "Paid" : "Failed";
        await _db.SaveChangesAsync();
        string resultCode = success ? "Success" : "EX";
        string resultMessage = success ? "" : "Kod geçersiz";
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Yönlendiriliyor...</title></head><body onload='document.forms[0].submit()'>");
        sb.Append("<form method='post' action='").Append(System.Net.WebUtility.HtmlEncode(entity.RedirectUrl)).Append("'>");
        sb.Append("<input type='hidden' name='hashValue' value='").Append(hashValue).Append("' />");
        sb.Append("<input type='hidden' name='resultCode' value='").Append(System.Net.WebUtility.HtmlEncode(resultCode)).Append("' />");
        sb.Append("<input type='hidden' name='resultMessage' value='").Append(System.Net.WebUtility.HtmlEncode(resultMessage)).Append("' />");
        sb.Append("<input type='hidden' name='trxCode' value='").Append(System.Net.WebUtility.HtmlEncode(entity.TrxCode)).Append("' />");
        sb.Append("<input type='hidden' name='OtherTrxCode' value='").Append(System.Net.WebUtility.HtmlEncode(entity.OtherTrxCode)).Append("' />");
        sb.Append("<noscript><button type='submit'>Devam</button></noscript></form></body></html>");
        // also send optional notify POST
        string? notify = _settings.NotifyUrl;
        if (!string.IsNullOrWhiteSpace(notify))
        {
            try
            {
                using var http = new HttpClient();
                var dict = new Dictionary<string, string>
                {
                    {"hashValue", hashValue},
                    {"resultCode", resultCode},
                    {"resultMessage", resultMessage},
                    {"trxCode", entity.TrxCode},
                    {"OtherTrxCode", entity.OtherTrxCode}
                };
                var resp = await http.PostAsync(notify, new FormUrlEncodedContent(dict));
                var okText = await resp.Content.ReadAsStringAsync();
                _logger.LogInformation("Notify POST to {notify} status {status} body '{body}'", notify, resp.StatusCode, okText);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Notify POST failed for trx={trx}", entity.OtherTrxCode);
            }
        }
        return Content(sb.ToString(), "text/html", Encoding.UTF8);
    }

    [HttpPost("verify3d")]
    public async Task<ActionResult<object>> Verify3D([FromForm] string trx, [FromForm] string hash, [FromForm] string dealerCode, [FromForm] string codeForHash)
    {
        var entity = await _db.Payments.FirstOrDefaultAsync(p => p.OtherTrxCode == trx);
        if (entity == null) return NotFound(new { verified = false, reason = "not_found" });
        bool success = string.Equals(entity.Status, "Paid", StringComparison.OrdinalIgnoreCase);
        string suffix = success ? "T" : "F";
        using SHA256 sha = SHA256.Create();
        string expected = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(entity.CodeForHash + suffix))).ToLowerInvariant();
        bool ok = string.Equals(expected, hash, StringComparison.OrdinalIgnoreCase);
        _logger.LogInformation("verify3d trx={trx} expected={expected} provided={hash} result={ok}", trx, expected, hash, ok);
        return Ok(new { verified = ok, expected, provided = hash });
    }

    [HttpGet("payments")]
    public async Task<ActionResult<IEnumerable<object>>> ListPayments()
    {
        var list = await _db.Payments
            .OrderByDescending(r => r.CreatedUtc)
            .Select(r => new { r.OtherTrxCode, r.TrxCode, r.ThreeDTrxCode, r.Amount, r.Currency, r.Status, r.CreatedUtc })
            .ToListAsync();
        return Ok(list);
    }

    [HttpGet("payments/other/{otherTrxCode}")]
    public async Task<ActionResult<object>> GetByOther(string otherTrxCode)
    {
        var r = await _db.Payments.FirstOrDefaultAsync(p => p.OtherTrxCode == otherTrxCode);
        return r is null ? NotFound() : Ok(r);
    }

    [HttpGet("payments/threeD/{threeDTrxCode}")]
    public async Task<ActionResult<object>> GetByThreeD(string threeDTrxCode)
    {
        var r = await _db.Payments.FirstOrDefaultAsync(p => p.ThreeDTrxCode == threeDTrxCode);
        return r is null ? NotFound() : Ok(r);
    }

    [HttpGet("payments/trx/{trxCode}")]
    public async Task<ActionResult<object>> GetByTrx(string trxCode)
    {
        var r = await _db.Payments.FirstOrDefaultAsync(p => p.TrxCode == trxCode);
        return r is null ? NotFound() : Ok(r);
    }
}
