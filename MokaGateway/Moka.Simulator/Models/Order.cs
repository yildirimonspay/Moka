namespace Moka.Simulator.Models;

public class Order
{
 public int Id { get; set; }
 public string Trx { get; set; } = string.Empty;
 public string TrxCode { get; set; } = string.Empty;
 public decimal Amount { get; set; }
 public string Currency { get; set; } = string.Empty;
 public string MaskedCard { get; set; } = string.Empty;
 public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
 public string Status { get; set; } = "Paid";
}
