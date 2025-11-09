namespace Moka.Simulator.Models;

public class PaymentCallbackViewModel
{
 public string? Trx { get; set; }
 public string? TrxCode { get; set; }
 public string? ResultCode { get; set; }
 public string? ResultMessage { get; set; }
 public bool Verified { get; set; }
 public string? LocalExpectedHash { get; set; }
 public bool ApiVerified { get; set; }
 public string? ApiExpectedHash { get; set; }
 public int? OrderId { get; set; }
}
