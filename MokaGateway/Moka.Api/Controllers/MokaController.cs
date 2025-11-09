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

        var auth = request.PaymentDealerAuthentication;
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
        var raw = (auth.DealerCode ?? string.Empty) + "MK" + (auth.Username ?? string.Empty) + "PD" + (auth.Password ?? string.Empty);
        using var sha = SHA256.Create();
        var expectedKey = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(auth.CheckKey) || !string.Equals(auth.CheckKey, expectedKey, StringComparison.OrdinalIgnoreCase))
        {
            return Ok(new DealerPaymentServicePaymentResult
            {
                ResultCode = "PaymentDealer.CheckPaymentDealerAuthentication.InvalidRequest",
                ResultMessage = "Invalid CheckKey"
            });
        }

        var otherTrx = request.PaymentDealerRequest.OtherTrxCode ?? Guid.NewGuid().ToString("N");
        var codeForHash = Guid.NewGuid().ToString().ToUpperInvariant();
        var redirectUrl = request.PaymentDealerRequest.RedirectUrl ?? _settings.RedirectUrl ?? "https://example.com/return";
        var trxCode = $"ORDER-{otherTrx}"; // simulate order id from bank

        // Persist
        var entity = new Data.PaymentEntity
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

        return Ok(new DealerPaymentServicePaymentResult
        {
            ResultCode = "Success",
            Data = new MokaData
            {
                Url = $"{redirectUrl}?OtherTrxCode={Uri.EscapeDataString(otherTrx)}",
                CodeForHash = codeForHash
            }
        });
    }

    [HttpPost("verify3d")]
    public async Task<ActionResult<object>> Verify3D([FromForm] string trx, [FromForm] string hash, [FromForm] string dealerCode, [FromForm] string codeForHash)
    {
        var password = _settings.Password ?? string.Empty;
        var raw = dealerCode + trx + codeForHash + password;
        using var sha = SHA256.Create();
        var expected = Convert.ToHexString(sha.ComputeHash(Encoding.UTF8.GetBytes(raw))).ToLowerInvariant();
        var ok = string.Equals(expected, hash, StringComparison.OrdinalIgnoreCase);
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
