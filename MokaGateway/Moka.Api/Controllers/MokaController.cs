using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using Moka.Contracts.Payments;
using Moka.Contracts.Settings;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using Swashbuckle.AspNetCore.Filters;
using System.Text;

namespace Moka.Api.Controllers;

[ApiController]
[Route("moka")]
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

    [HttpPost("pay")]
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

        PaymentDealerAuthentication auth = request.PaymentDealerAuthentication;
        if (auth is null)
        {
            return Ok(new DealerPaymentServicePaymentResult
            {
                ResultCode = "PaymentDealer.CheckPaymentDealerAuthentication.InvalidRequest",
                ResultMessage = "Missing auth"
            });
        }

        // Validate account against configured settings (simple demo check)
        if (!string.Equals(auth.DealerCode, _settings.DealerCode, StringComparison.Ordinal)
            || !string.Equals(auth.Username, _settings.Username, StringComparison.Ordinal)
            || !string.Equals(auth.Password, _settings.Password, StringComparison.Ordinal))
        {
            return Ok(new DealerPaymentServicePaymentResult
            {
                ResultCode = "PaymentDealer.CheckPaymentDealerAuthentication.InvalidAccount",
                ResultMessage = "Invalid dealer credentials"
            });
        }

        // Validate CheckKey by spec: SHA256(DealerCode+"MK"+Username+"PD"+Password)
        string raw = (auth.DealerCode ?? string.Empty) + "MK" + (auth.Username ?? string.Empty) + "PD" + (auth.Password ?? string.Empty);
        using SHA256 sha = SHA256.Create();
        string expectedKey = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(auth.CheckKey) || !string.Equals(auth.CheckKey, expectedKey, StringComparison.OrdinalIgnoreCase))
        {
            return Ok(new DealerPaymentServicePaymentResult
            {
                ResultCode = "PaymentDealer.CheckPaymentDealerAuthentication.InvalidRequest",
                ResultMessage = "Invalid CheckKey"
            });
        }

        string otherTrx = request.PaymentDealerRequest.OtherTrxCode ?? Guid.NewGuid().ToString("N");
        string codeForHash = Guid.NewGuid().ToString().ToUpperInvariant();
        string redirectUrl = request.PaymentDealerRequest.RedirectUrl ?? _settings.RedirectUrl ?? "https://example.com/return";
        string trxCode = $"ORDER-{otherTrx}"; // simulate order id from bank

        // Persist
        Data.PaymentEntity entity = new Data.PaymentEntity
        {
            OtherTrxCode = otherTrx,
            TrxCode = trxCode,
            CodeForHash = codeForHash,
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
        string threeDUrl = $"{baseUrl}/moka/threeD?trx={Uri.EscapeDataString(otherTrx)}&redirect={Uri.EscapeDataString(redirectUrl)}";

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

    [HttpGet("threeD")]
    public async Task<IActionResult> ThreeD([FromQuery] string trx, [FromQuery] string redirect)
    {
        var entity = await _db.Payments.FirstOrDefaultAsync(p => p.OtherTrxCode == trx);
        if (entity == null) return NotFound("Transaction not found");
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>3D Secure Kod</title></head><body>");
        sb.Append("<h3>3D Güvenlik Doðrulamasý</h3>");
        sb.Append("<p>Telefonunuza gelen4 haneli kodu giriniz (demo:1234).</p>");
        sb.Append("<form method='post' action='/moka/threeD'>");
        sb.Append("<input type='hidden' name='trx' value='")
          .Append(System.Net.WebUtility.HtmlEncode(trx)).Append("' />");
        sb.Append("<input type='hidden' name='redirect' value='")
          .Append(System.Net.WebUtility.HtmlEncode(redirect)).Append("' />");
        sb.Append("<input name='code' maxlength='4' value='' autofocus pattern='[0-9]{4}' required />");
        sb.Append("<button type='submit'>Doðrula</button>");
        sb.Append("</form></body></html>");
        var html = sb.ToString();
        return Content(html, "text/html", Encoding.UTF8);
    }

    [HttpPost("threeD")]
    public async Task<IActionResult> ThreeDSubmit([FromForm] string trx, [FromForm] string redirect, [FromForm] string code)
    {
        var entity = await _db.Payments.FirstOrDefaultAsync(p => p.OtherTrxCode == trx);
        if (entity == null) return NotFound("Transaction not found");
        bool success = code == "1234"; // demo validation
        string dealerCode = _settings.DealerCode ?? string.Empty;
        string password = _settings.Password ?? string.Empty;
        string hashRaw = dealerCode + trx + entity.CodeForHash + password;
        using SHA256 sha = SHA256.Create();
        string hash = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(hashRaw))).ToLowerInvariant();
        entity.Status = success ? "Paid" : "Failed";
        await _db.SaveChangesAsync();
        string resultCode = success ? "" : "EX";
        string resultMessage = success ? "" : "Kod geçersiz";
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Yönlendiriliyor...</title></head><body onload='document.forms[0].submit()'>");
        sb.Append("<form method='post' action='")
          .Append(System.Net.WebUtility.HtmlEncode(redirect)).Append("'>");
        sb.Append("<input type='hidden' name='hashValue' value='")
          .Append(hash).Append("' />");
        sb.Append("<input type='hidden' name='resultCode' value='")
          .Append(System.Net.WebUtility.HtmlEncode(resultCode)).Append("' />");
        sb.Append("<input type='hidden' name='resultMessage' value='")
          .Append(System.Net.WebUtility.HtmlEncode(resultMessage)).Append("' />");
        sb.Append("<input type='hidden' name='trxCode' value='")
          .Append(System.Net.WebUtility.HtmlEncode(entity.TrxCode)).Append("' />");
        sb.Append("<input type='hidden' name='OtherTrxCode' value='")
          .Append(System.Net.WebUtility.HtmlEncode(trx)).Append("' />");
        sb.Append("<noscript><button type='submit'>Devam</button></noscript>");
        sb.Append("</form></body></html>");
        var html = sb.ToString();
        return Content(html, "text/html", Encoding.UTF8);
    }

    [HttpPost("verify3d")]
    public async Task<ActionResult<object>> Verify3D([FromForm] string trx, [FromForm] string hash, [FromForm] string dealerCode, [FromForm] string codeForHash)
    {
        string password = _settings.Password ?? string.Empty;
        string raw = dealerCode + trx + codeForHash + password;
        using SHA256 sha = SHA256.Create();
        string expected = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
        bool ok = string.Equals(expected, hash, StringComparison.OrdinalIgnoreCase);
        _logger.LogInformation("3D verification trx={trx} expected={expected} provided={hash} result={res}", trx, expected, hash, ok);

        var entity = await _db.Payments.FirstOrDefaultAsync(p => p.OtherTrxCode == trx);
        if (entity != null)
        {
            entity.Status = ok ? "Paid" : "Failed";
            await _db.SaveChangesAsync();
        }
        return Ok(new { verified = ok, expected, provided = hash });
    }

    [HttpGet("payments")]
    public async Task<ActionResult<IEnumerable<object>>> ListPayments()
    {
        var list = await _db.Payments
            .OrderByDescending(r => r.CreatedUtc)
            .Select(r => new
            {
                r.OtherTrxCode,
                r.TrxCode,
                r.Amount,
                r.Currency,
                r.Status,
                r.CreatedUtc
            })
            .ToListAsync();
        return Ok(list);
    }

    [HttpGet("payments/other/{otherTrxCode}")]
    public async Task<ActionResult<object>> GetByOther(string otherTrxCode)
    {
        var r = await _db.Payments.FirstOrDefaultAsync(p => p.OtherTrxCode == otherTrxCode);
        return r is null ? NotFound() : Ok(r);
    }

    [HttpGet("payments/trx/{trxCode}")]
    public async Task<ActionResult<object>> GetByTrx(string trxCode)
    {
        var r = await _db.Payments.FirstOrDefaultAsync(p => p.TrxCode == trxCode);
        return r is null ? NotFound() : Ok(r);
    }
}
