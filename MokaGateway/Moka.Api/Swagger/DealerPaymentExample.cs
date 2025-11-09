using Moka.Contracts.Payments;
using Swashbuckle.AspNetCore.Filters;

namespace Moka.Api.Swagger;

public class DealerPaymentExample : IExamplesProvider<DealerPaymentServicePaymentRequest>
{
 public DealerPaymentServicePaymentRequest GetExamples() => new()
 {
 PaymentDealerAuthentication = new()
 {
 DealerCode = "D123",
 Username = "api-user",
 Password = "secret",
 CheckKey = "<sha256(DealerCode+MK+Username+PD+Password)>"
 },
 PaymentDealerRequest = new()
 {
 CardHolderFullName = "Ali Yýlmaz",
 CardNumber = "5555666677778888",
 ExpMonth = "09",
 ExpYear = "2027",
 CvcNumber = "123",
 Amount =27.50m,
 Currency = "TL",
 InstallmentNumber =1,
 ClientIP = "127.0.0.1",
 OtherTrxCode = DateTime.UtcNow.ToString("yyyyMMddHHmmss"),
 ReturnHash =1,
 RedirectUrl = "http://localhost:5283/DealerPayment/Callback"
 }
 };
}
