using System.Collections.Generic;

namespace Moka.Simulator.Models;

public class DealerPaymentServicePaymentResult
{
    public DealerPaymentServicePaymentResult()
    {
    Warnings = new List<string>();
    }

public MokaData? Data { get; set; }
    public string? ResultCode { get; set; }
    public string? ResultMessage { get; set; }
    public string? Exception { get; set; }

public List<string> Warnings { get; set; }
}
