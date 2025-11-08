using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using Moka.Contracts.Payments;

namespace Moka.Api.Controllers;

[ApiController]
[Route("moka")]
public class MokaController : ControllerBase
{
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

        var codeForHash = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        var redirectUrl = request.PaymentDealerRequest.RedirectUrl ?? "https://example.com/return";

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
