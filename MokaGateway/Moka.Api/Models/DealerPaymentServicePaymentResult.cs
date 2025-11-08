namespace Moka.Api.Models;

public class DealerPaymentServicePaymentResult
{
 public MokaData? Data { get; set; }
 public string? ResultCode { get; set; }
 public string? ResultMessage { get; set; }
 public string? Exception { get; set; }
 public List<string> Warnings { get; set; } = new();
}

public class MokaData
{
 public string? Url { get; set; }
 public string? CodeForHash { get; set; }
}
