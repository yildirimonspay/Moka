namespace Moka.Contracts.Payments;

public class CallbackDto
{
 public string? trx { get; set; }
 public string? resultCode { get; set; }
 public string? resultMessage { get; set; }
 public string? hashValue { get; set; }
 public string? trxCode { get; set; }
 public string? OtherTrxCode { get; set; }
 public string? authorizationCode { get; set; }
 public string? nonce { get; set; }
 public string? signature { get; set; }
}
