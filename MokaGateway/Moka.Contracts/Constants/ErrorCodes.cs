namespace Moka.Contracts.Constants;

public static class ErrorCodes
{
 // General
 public const string EX = "EX";
 public const string InvalidRequest = "InvalidRequest";

 // DoDirectPayment3dRequest
 public const string RedirectUrlRequired = "PaymentDealer.DoDirectPayment3dRequest.RedirectUrlRequired";
 public const string RedirectUrlMustBeHttps = "PaymentDealer.DoDirectPayment3dRequest.RedirectUrlMustBeHttps";
 public const string InvalidRedirectUrl = "PaymentDealer.DoDirectPayment3dRequest.InvalidRedirectUrl";
 public const string InvalidRedirectUrlDomain = "PaymentDealer.DoDirectPayment3dRequest.InvalidRedirectUrlDomain";
}
