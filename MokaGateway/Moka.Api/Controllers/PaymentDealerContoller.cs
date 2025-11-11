using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Moka.Contracts.Constants;
using Moka.Contracts.Helper;
using Moka.Contracts.Payments;
using Moka.Contracts.Settings;
using Swashbuckle.AspNetCore.Filters;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.RateLimiting;

namespace Moka.Api.Controllers;

[ApiController]
[Route("PaymentDealer")] // spec base route
public class PaymentDealerContoller : ControllerBase
{
    private readonly ILogger<PaymentDealerContoller> _logger;
    private readonly MokaSettings _settings;
    private readonly Data.MokaDbContext _db;
    private readonly IHttpClientFactory _httpClientFactory;

    public PaymentDealerContoller(ILogger<PaymentDealerContoller> logger, IOptions<MokaSettings> settings, Data.MokaDbContext db, IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _settings = settings.Value;
        _db = db;
        _httpClientFactory = httpClientFactory;
    }

    [EnableRateLimiting("gateway")]
    [HttpPost("DoDirectPaymentThreeD")] // attach rate limiter to critical endpoint
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
            if (digits.Length >= 10) maskedCard = digits.Substring(0, 6) + new string('*', digits.Length - 10) + digits[^4..];
        }
        _logger.LogInformation("3D request Amount={amt} Currency={cur} MaskedCard={mc}", request.PaymentDealerRequest?.Amount, request.PaymentDealerRequest?.Currency, maskedCard);

        try
        {
            var req = request.PaymentDealerRequest;
            // RedirectUrl required
            if (string.IsNullOrWhiteSpace(req.RedirectUrl))
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.RedirectUrlRequired", ResultMessage = "RedirectUrl required", Data = null });
            }
            // Currency whitelist
            var allowed = new[] { "TL", "USD", "EUR", "GBP", null, string.Empty };
            if (!allowed.Contains(req.Currency))
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.InvalidCurrencyCode", ResultMessage = "Invalid currency", Data = null });
            }
            // Installment rules
            if (req.InstallmentNumber < 0 || req.InstallmentNumber > 12)
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.InvalidInstallmentNumber", ResultMessage = "Invalid installment", Data = null });
            }
            // Card vs Token exclusivity
            if (string.IsNullOrWhiteSpace(req.CardNumber) && string.IsNullOrWhiteSpace(req.CardToken))
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.OnlyCardTokenOrCardNumber", ResultMessage = "Provide card or token", Data = null });
            }
            if (!string.IsNullOrWhiteSpace(req.CardNumber) && !string.IsNullOrWhiteSpace(req.CardToken))
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.OnlyCardTokenOrCardNumber", ResultMessage = "Provide only one of card or token", Data = null });
            }
            // ReturnHash must be1
            if (req.ReturnHash != 1)
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.InvalidRequest", ResultMessage = "ReturnHash must be1", Data = null });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Validation phase failed");
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "EX", ResultMessage = "Internal error", Data = null });
        }

        // IP whitelist (optional)
        if (_settings.AllowedIps != null && _settings.AllowedIps.Length > 0)
        {
            var clientIp = request.PaymentDealerRequest.ClientIP ?? string.Empty;
            if (!_settings.AllowedIps.Contains(clientIp))
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.IpAddressNotAllowed", ResultMessage = "IP not allowed", Data = null });
            }
        }

        var s = _settings;
        var reqPay = request.PaymentDealerRequest;
        // Tokenization permissions
        if (!string.IsNullOrWhiteSpace(reqPay.CardToken) && s.AllowTokenization == false)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.TokenizationNotAvailableForDealer", ResultMessage = "Tokenization not allowed", Data = null });
        }
        if (reqPay.IsTokenized == 1 && s.AllowTokenization == false)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.TokenizationNotAvailableForDealer", ResultMessage = "Tokenization not allowed", Data = null });
        }
        if (reqPay.IsTokenized == 1 && !string.IsNullOrWhiteSpace(reqPay.CardToken))
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.CardTokenCannotUseWithSaveCard", ResultMessage = "Cannot use token and save card", Data = null });
        }
        if (!string.IsNullOrWhiteSpace(reqPay.CardToken) && !string.IsNullOrWhiteSpace(reqPay.CardNumber))
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.OnlyCardTokenOrCardNumber", ResultMessage = "Only card token or card number allowed", Data = null });
        }

        // Pool payment permissions
        if (reqPay.IsPoolPayment == 1 && s.AllowPoolPayments == false)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.PoolPaymentNotAvailableForDealer", ResultMessage = "Pool payment not allowed", Data = null });
        }
        if (reqPay.IsPoolPayment == 0 && s.ForcePoolPayments)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.PoolPaymentRequiredForDealer", ResultMessage = "Pool payment required", Data = null });
        }

        // PreAuth permissions
        if (reqPay.IsPreAuth == 1 && s.AllowPreAuth == false)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.AuthorizationForbiddenForThisDealer", ResultMessage = "PreAuth forbidden", Data = null });
        }
        if (reqPay.IsPreAuth == 0 && s.AllowPreAuth && reqPay.IsPoolPayment == 0 && reqPay.InstallmentNumber > 1)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.PaymentMustBeAuthorization", ResultMessage = "Payment must be authorization for installments", Data = null });
        }

        // Installment foreign currency restriction
        if (!string.IsNullOrWhiteSpace(reqPay.Currency) && reqPay.Currency != "TL" && reqPay.InstallmentNumber > 1)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.InstallmentNotAvailableForForeignCurrencyTransaction", ResultMessage = "No installments for foreign currency", Data = null });
        }
        if (!string.IsNullOrWhiteSpace(reqPay.Currency) && s.ForeignCurrenciesEnabled != null && !s.ForeignCurrenciesEnabled.Contains(reqPay.Currency) && reqPay.Currency != "TL")
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.ForeignCurrencyNotAvailableForThisDealer", ResultMessage = "Foreign currency not allowed", Data = null });
        }

        // SubMerchant name validation (use SubMerchantName field)
        if (!string.IsNullOrWhiteSpace(reqPay.SubMerchantName) && s.AllowedSubMerchants != null && !s.AllowedSubMerchants.Contains(reqPay.SubMerchantName))
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.InvalidSubMerchantName", ResultMessage = "Invalid sub merchant", Data = null });
        }

        // Software validation
        if (!string.IsNullOrWhiteSpace(reqPay.Software) && s.AllowedSoftware != null && !s.AllowedSoftware.Contains(reqPay.Software))
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.ChannelPermissionNotAvailable", ResultMessage = "Software/channel not permitted", Data = null });
        }

        // Product basket validation for known codes
        if (reqPay.BasketProducts != null && reqPay.BasketProducts.Count > 0 && s.KnownProductCodes != null)
        {
            foreach (var bp in reqPay.BasketProducts)
            {
                if (!string.IsNullOrWhiteSpace(bp.ProductCode) && !s.KnownProductCodes.Contains(bp.ProductCode))
                {
                    return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.BasketProductNotFoundInYourProductList", ResultMessage = "Unknown product", Data = null });
                }
                if (string.IsNullOrWhiteSpace(bp.ProductCode) && bp.ProductId == 0)
                {
                    return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.MustBeOneOfDealerProductIdOrProductCode", ResultMessage = "Need product id or code", Data = null });
                }
            }
        }

        // Run data annotation validations explicitly for complex codes
        var ctx = new ValidationContext(request.PaymentDealerRequest);
        var results = new List<ValidationResult>();
        if (!Validator.TryValidateObject(request.PaymentDealerRequest, ctx, results, true))
        {
            var first = results.FirstOrDefault();
            if (first != null)
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = first.ErrorMessage, ResultMessage = string.Empty, Data = null });
            }
        }

        // Daily limits (simple aggregate for today)
        DateTime today = DateTime.UtcNow.Date;
        decimal dealerToday = await _db.Payments.Where(p => p.CreatedUtc >= today && p.CreatedUtc < today.AddDays(1)).SumAsync(p => p.Amount);
        if (dealerToday + request.PaymentDealerRequest.Amount > _settings.DailyDealerLimit)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.CheckDealerPaymentLimits.DailyDealerLimitExceeded", ResultMessage = "Dealer daily limit exceeded", Data = null });
        }
        string cardBin = new string((request.PaymentDealerRequest.CardNumber ?? string.Empty).Where(char.IsDigit).ToArray());
        cardBin = cardBin.Length >= 6 ? cardBin.Substring(0, 6) : cardBin;
        decimal cardToday = await _db.Payments.Where(p => p.CreatedUtc >= today && p.CreatedUtc < today.AddDays(1) && p.CardBin == cardBin).SumAsync(p => p.Amount);
        if (cardToday + request.PaymentDealerRequest.Amount > _settings.DailyCardLimit)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.CheckDealerPaymentLimits.DailyCardLimitExceeded", ResultMessage = "Card daily limit exceeded", Data = null });
        }
        // Max installment dealer-level
        if (request.PaymentDealerRequest.InstallmentNumber > _settings.MaxInstallment)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.ThisInstallmentNumberNotAvailableForDealer", ResultMessage = "Installment exceeds dealer max", Data = null });
        }

        // Virtual POS availability by BIN (simulate). If BIN not allowed => VirtualPosNotFound
        if (_settings.AllowedBins != null && _settings.AllowedBins.Length > 0 && !string.IsNullOrWhiteSpace(cardBin) && !_settings.AllowedBins.Any(b => cardBin.StartsWith(b)))
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.CheckPaymentDealerAuthentication.VirtualPosNotFound", ResultMessage = "Virtual POS not found for BIN", Data = null });
        }
        // Installment number exceeds virtual pos capability
        if (request.PaymentDealerRequest.InstallmentNumber > _settings.MaxInstallmentPerVirtualPos)
        {
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.ThisInstallmentNumberNotAvailableForVirtualPos", ResultMessage = "Installment exceeds virtual pos limit", Data = null });
        }
        // Commission required for installments
        if (_settings.RequireCommissionForInstallments && request.PaymentDealerRequest.InstallmentNumber > 1 && (request.PaymentDealerRequest.CommissionRate == null || request.PaymentDealerRequest.GroupCommissionRate == null))
        {
            if (request.PaymentDealerRequest.CommissionRate == null)
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.DealerCommissionRateNotFound", ResultMessage = "Dealer commission missing", Data = null });
            }
            if (request.PaymentDealerRequest.GroupCommissionRate == null)
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.DealerGroupCommissionRateNotFound", ResultMessage = "Group commission missing", Data = null });
            }
        }

        // enforce RedirectUrl allowlist and https (refactored)
        string? redirectCandidate = request.PaymentDealerRequest.RedirectUrl ?? _settings.RedirectUrl;
        if (!TryValidateRedirect(redirectCandidate, _settings.RedirectDomainWhitelist, _settings.RedirectDomainsPerDealer, request.PaymentDealerAuthentication?.DealerCode, out var redirectError))
        {
            return Ok(R(redirectError!));
        }
        // generate OTP per transaction
        string otp = Random.Shared.Next(1000,9999).ToString();
        string otpHash;
        using (var shaOtp = SHA256.Create())
        {
            otpHash = Convert.ToHexString(shaOtp.ComputeHash(Encoding.UTF8.GetBytes(otp))).ToLowerInvariant();
        }
        // generate transaction identifiers and redirect plumbing (previously removed)
        string otherTrx = request.PaymentDealerRequest.OtherTrxCode ?? Guid.NewGuid().ToString("N");
        string codeForHash = Guid.NewGuid().ToString().ToUpperInvariant();
        string nonce = Guid.NewGuid().ToString("N");
        string redirectUrl = request.PaymentDealerRequest.RedirectUrl ?? _settings.RedirectUrl ?? "https://example.com/return";
        if (!redirectUrl.Contains("?")) redirectUrl += "?nonce=" + Uri.EscapeDataString(nonce); else redirectUrl += "&nonce=" + Uri.EscapeDataString(nonce);
        string trxCode = Random.Shared.NextInt64(100000000000,999999999999).ToString();
        string threeDTrxCode = Guid.NewGuid().ToString("N");
        string cardBinForEntity = new string((request.PaymentDealerRequest.CardNumber ?? string.Empty).Where(char.IsDigit).ToArray());
        cardBinForEntity = cardBinForEntity.Length >=6 ? cardBinForEntity.Substring(0,6) : cardBinForEntity;
        string provisionalAuthCode = string.Empty;
        DateTime otpExpiry = DateTime.UtcNow.AddMinutes(5);

        // create payment entity
        try
        {
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
                CardBin = cardBinForEntity,
                AuthorizationCode = provisionalAuthCode,
                OtpExpiresUtc = otpExpiry,
                OtpFailCount =0,
                OtpMaxAttempts =3,
                CreatedUtc = DateTime.UtcNow,
                OtpHash = otpHash,
                OtpPlainTest = _settings.Mode?.Equals("Test", StringComparison.OrdinalIgnoreCase) == true ? otp : null,
            };
            _db.Payments.Add(entity);
            await _db.SaveChangesAsync();

            // Commission enrichment (simple demo): if installment>1 and commission provided add warning if rate <1%
            if (request.PaymentDealerRequest.InstallmentNumber > 1 && request.PaymentDealerRequest.CommissionRate.HasValue && request.PaymentDealerRequest.CommissionRate.Value < 0.01m)
            {
                return Ok(new DealerPaymentServicePaymentResult { ResultCode = "PaymentDealer.DoDirectPayment3dRequest.DealerCommissionRateNotFound", ResultMessage = "Commission rate too low", Data = null });
            }

            string baseUrl = $"{Request.Scheme}://{Request.Host}";
            string threeDUrl = $"{baseUrl}/PaymentDealer/PaymentDealerThreeDProcess?threeDTrxCode={Uri.EscapeDataString(threeDTrxCode)}";
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "Success", Data = new MokaData { Url = threeDUrl, CodeForHash = codeForHash } });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Pay failed");
            return Ok(new DealerPaymentServicePaymentResult { ResultCode = "EX", ResultMessage = "Internal error", Data = null });
        }
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
        sb.Append("<button type='submit'>Doðrula</button></form>");
        // OTP info
        var remaining = Math.Max(0, entity.OtpMaxAttempts - entity.OtpFailCount);
        var expiresIn = entity.OtpExpiresUtc.HasValue ? (int)(entity.OtpExpiresUtc.Value - DateTime.UtcNow).TotalSeconds : 0;
        sb.Append($"<p>Kalan deneme: {remaining}, Süre(sn): {expiresIn}</p>");
        sb.Append("</body></html>");

        // In ThreeD GET add cache-control headers
        Response.Headers["Cache-Control"] = "no-store, no-cache, max-age=0";
        Response.Headers["Pragma"] = "no-cache";
        Response.Headers["Expires"] = "0";

        return Content(sb.ToString(), "text/html", Encoding.UTF8);
    }

    [HttpPost("PaymentDealerThreeDProcess")]
    public async Task<IActionResult> ThreeDSubmit([FromForm] string threeDTrxCode, [FromForm] string code)
    {
        var entity = await _db.Payments.FirstOrDefaultAsync(p => p.ThreeDTrxCode == threeDTrxCode);
        if (entity == null) return NotFound("Transaction not found");
        // OTP expiry check
        if (entity.OtpExpiresUtc.HasValue && DateTime.UtcNow > entity.OtpExpiresUtc.Value)
        {
            entity.Status = "Failed";
            await _db.SaveChangesAsync();
            // client-side auto POST to merchant error endpoint
            var dict = BuildReturnFields(entity, success: false, msg: "OTP expired");
            return RemotePostUtil.ToUrlAutoPost(entity.RedirectUrl, dict);
        }
        bool success = false; // replaced previous inline success calc
        {
            // verify OTP using constant-time hash compare
            string providedHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(code))).ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(entity.OtpHash))
            {
                try
                {
                    success = CryptographicOperations.FixedTimeEquals(Convert.FromHexString(entity.OtpHash), Convert.FromHexString(providedHash));
                }
                catch { success = false; }
            }
        }
        if (!success)
        {
            entity.OtpFailCount++;
            await _db.SaveChangesAsync();
            if (entity.OtpFailCount >= entity.OtpMaxAttempts)
            {
                entity.Status = "Failed";
                await _db.SaveChangesAsync();
                var dictMax = BuildReturnFields(entity, success: false, msg: "Too many invalid attempts");
                return RemotePostUtil.ToUrlAutoPost(entity.RedirectUrl, dictMax);
            }
            var dictFail = BuildReturnFields(entity, success: false, msg: "Invalid OTP");
            return RemotePostUtil.ToUrlAutoPost(entity.RedirectUrl, dictFail);
        }
        // OTP verified; wait for bank authorization callback
        entity.Status = "OtpVerified";
        await _db.SaveChangesAsync();
        return Content($"<html><body><p>OTP doðrulandý. Banka provizyonu bekleniyor...</p><p>threeDTrxCode: {entity.ThreeDTrxCode}</p></body></html>", "text/html", Encoding.UTF8);
    }

    [EnableRateLimiting("gateway")]
    [HttpPost("BankAuthorizationCallback")]
    public async Task<ActionResult<object>> BankAuthorizationCallback([FromForm] string threeDTrxCode, [FromForm] string authResult)
    {
        var entity = await _db.Payments.FirstOrDefaultAsync(p => p.ThreeDTrxCode == threeDTrxCode);
        if (entity == null) return NotFound(new { ok = false, reason = "not_found" });
        bool success = string.Equals(authResult, "OK", StringComparison.OrdinalIgnoreCase);
        if (success)
        {
            // compute success hash and post to merchant
            if (string.IsNullOrWhiteSpace(entity.AuthorizationCode))
                entity.AuthorizationCode = Guid.NewGuid().ToString("N").Substring(0,12).ToUpperInvariant();
            string suffix = "T";
            using SHA256 sha = SHA256.Create();
            string hashValue = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(entity.CodeForHash + suffix))).ToLowerInvariant();
            entity.Status = "Paid";
            await _db.SaveChangesAsync();
            try
            {
                var http = _httpClientFactory.CreateClient("merchant-callback");
                http.Timeout = TimeSpan.FromSeconds(10);
                string ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                string jti = Guid.NewGuid().ToString("N");
                entity.AuthorizationCallbackJti = jti;
                await _db.SaveChangesAsync();
                var payload = $"trxCode={entity.TrxCode}&OtherTrxCode={entity.OtherTrxCode}&resultCode=Success&hashValue={hashValue}&nonce={entity.Nonce}&ts={ts}&jti={jti}";
                var sig = ComputeHmac(payload, _settings.RedirectHmacSecret);
                var dict = new Dictionary<string, string>
                {
                    {"hashValue", hashValue},
                    {"resultCode", "Success"},
                    {"resultMessage", string.Empty},
                    {"trxCode", entity.TrxCode},
                    {"OtherTrxCode", entity.OtherTrxCode},
                    {"nonce", entity.Nonce},
                    {"authorizationCode", entity.AuthorizationCode},
                    {"ts", ts},
                    {"jti", jti},
                    {"signature", sig}
                };
                var resp = await http.PostAsync(entity.RedirectUrl, new FormUrlEncodedContent(dict));
                if (!resp.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Merchant redirect returned {status}", resp.StatusCode);
                }
                // optional notify
                if (!string.IsNullOrWhiteSpace(_settings.NotifyUrl))
                {
                    try
                    {
                        var notifyResp = await http.PostAsync(_settings.NotifyUrl, new FormUrlEncodedContent(dict));
                        var body = await notifyResp.Content.ReadAsStringAsync();
                        if (!notifyResp.IsSuccessStatusCode || !string.Equals(body.Trim(), "OK", StringComparison.OrdinalIgnoreCase))
                        {
                            _logger.LogWarning("Notify did not return OK. Status {status} Body '{body}'", notifyResp.StatusCode, body);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Notify call failed");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Auto merchant redirect POST failed");
            }
        }
        else
        {
            // failure: post failure back too
            string suffix = "F";
            using SHA256 sha = SHA256.Create();
            string hashValue = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(entity.CodeForHash + suffix))).ToLowerInvariant();
            entity.Status = "Failed";
            await _db.SaveChangesAsync();
            try
            {
                var http = _httpClientFactory.CreateClient("merchant-callback");
                http.Timeout = TimeSpan.FromSeconds(10);
                string ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
                string jti = Guid.NewGuid().ToString("N");
                entity.AuthorizationCallbackJti = jti;
                await _db.SaveChangesAsync();
                var payloadF = $"trxCode={entity.TrxCode}&OtherTrxCode={entity.OtherTrxCode}&resultCode=EX&hashValue={hashValue}&nonce={entity.Nonce}&ts={ts}&jti={jti}";
                var sigF = ComputeHmac(payloadF, _settings.RedirectHmacSecret);
                var fdict = new Dictionary<string, string>
                {
                    {"hashValue", hashValue},
                    {"resultCode", "EX"},
                    {"resultMessage", "Authorization failed"},
                    {"trxCode", entity.TrxCode},
                    {"OtherTrxCode", entity.OtherTrxCode},
                    {"nonce", entity.Nonce},
                    {"ts", ts},
                    {"jti", jti},
                    {"signature", sigF}
                };
                var fResp = await http.PostAsync(entity.RedirectUrl, new FormUrlEncodedContent(fdict));
                if (!fResp.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Merchant redirect (failure) returned {status}", fResp.StatusCode);
                }
                if (!string.IsNullOrWhiteSpace(_settings.NotifyUrl))
                {
                    try
                    {
                        var notifyResp = await http.PostAsync(_settings.NotifyUrl, new FormUrlEncodedContent(fdict));
                        var body = await notifyResp.Content.ReadAsStringAsync();
                        if (!notifyResp.IsSuccessStatusCode || !string.Equals(body.Trim(), "OK", StringComparison.OrdinalIgnoreCase))
                        {
                            _logger.LogWarning("Notify (failure) did not return OK. Status {status} Body '{body}'", notifyResp.StatusCode, body);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Notify failure call failed");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Auto merchant redirect POST (failure) failed");
            }
        }
        return Ok(new { ok = true, paid = success });
    }

    // replace hardcoded codes where simple mapping is possible
    private DealerPaymentServicePaymentResult R(string code, string? msg = null) => new DealerPaymentServicePaymentResult { ResultCode = code, ResultMessage = msg, Data = null };

    // In BuildReturnFields and merchant callback, use SignatureUtil to compute canonical payload
    private Dictionary<string, string> BuildReturnFields(Data.PaymentEntity entity, bool success, string msg = "")
    {
        string suffix = success ? "T" : "F";
        using SHA256 sha = SHA256.Create();
        string hashValue = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(entity.CodeForHash + suffix))).ToLowerInvariant();
        var map = new Dictionary<string,string?>
        {
        ["hashValue"] = hashValue,
        ["nonce"] = entity.Nonce,
        ["OtherTrxCode"] = entity.OtherTrxCode,
        ["resultCode"] = success?"Success":"EX",
        ["trxCode"] = entity.TrxCode
        };
        var payload = SignatureUtil.BuildCanonical(map);
        var sig = SignatureUtil.ComputeHmacHex(payload, _settings.RedirectHmacSecret);
        var dict = new Dictionary<string, string>
        {
        {"hashValue", hashValue},
        {"resultCode", success?"Success":"EX"},
        {"resultMessage", msg},
        {"trxCode", entity.TrxCode},
        {"OtherTrxCode", entity.OtherTrxCode},
        {"nonce", entity.Nonce}
        };
        if (success && !string.IsNullOrWhiteSpace(entity.AuthorizationCode)) dict.Add("authorizationCode", entity.AuthorizationCode);
        if (!string.IsNullOrWhiteSpace(sig)) dict.Add("signature", sig);
        return dict;
    }

    private static string ComputeHmac(string data, string? secret)
    {
        if (string.IsNullOrEmpty(secret)) return string.Empty;
        using var h = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(data))).ToLowerInvariant();
    }

    private static bool TryValidateRedirect(string? url, string[]? whitelist, Dictionary<string,string[]>? perDealer, string? dealerCode, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(url)) { error = "PaymentDealer.DoDirectPayment3dRequest.RedirectUrlRequired"; return false; }
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) { error = "PaymentDealer.DoDirectPayment3dRequest.InvalidRedirectUrl"; return false; }
        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) { error = "PaymentDealer.DoDirectPayment3dRequest.RedirectUrlMustBeHttps"; return false; }
        var domains = (perDealer != null && dealerCode != null && perDealer.TryGetValue(dealerCode, out var list)) ? list : whitelist;
        if (domains != null && !domains.Contains(uri.Host, StringComparer.OrdinalIgnoreCase)) { error = "PaymentDealer.DoDirectPayment3dRequest.InvalidRedirectUrlDomain"; return false; }
        return true;
    }
}
