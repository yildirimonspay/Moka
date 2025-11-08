using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using Moka.Contracts.Payments;
using Moka.Contracts.Settings;
using Microsoft.Extensions.Options;

namespace Moka.Api.Controllers;

[ApiController]
[Route("moka")]
public class MokaController : ControllerBase
{
    private readonly ILogger<MokaController> _logger;
    private readonly MokaSettings _settings;

    public MokaController(ILogger<MokaController> logger, IOptions<MokaSettings> settings)
    {
        _logger = logger;
        _settings = settings.Value;
    }

    [HttpPost("pay")]
    public ActionResult<DealerPaymentServicePaymentResult> Pay([FromBody] DealerPaymentServicePaymentRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(new DealerPaymentServicePaymentResult { ResultCode = "InvalidRequest", ResultMessage = "Validation failed", Warnings = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList() });

        if (string.IsNullOrWhiteSpace(request.PaymentDealerAuthentication.CheckKey))
        {
            return Ok(new DealerPaymentServicePaymentResult
            {
                ResultCode = "PaymentDealer.CheckPaymentDealerAuthentication.InvalidRequest",
                ResultMessage = "Missing CheckKey",
                Warnings = new List<string> { "CheckKey is required" }
            });
        }

        _logger.LogInformation("Incoming payment OtherTrxCode={OtherTrxCode} Dealer={Dealer} Mode={Mode}", request.PaymentDealerRequest.OtherTrxCode, request.PaymentDealerAuthentication.DealerCode, _settings.Mode);

        var codeForHash = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        var redirectUrl = request.PaymentDealerRequest.RedirectUrl ?? _settings.RedirectUrl ?? "https://example.com/return";

        return Ok(new DealerPaymentServicePaymentResult
        {
            ResultCode = "Success",
            Data = new MokaData
            {
                Url = $"{redirectUrl}?trx={Uri.EscapeDataString(request.PaymentDealerRequest.OtherTrxCode ?? string.Empty)}",
                CodeForHash = codeForHash
            }
        });
    }
}
