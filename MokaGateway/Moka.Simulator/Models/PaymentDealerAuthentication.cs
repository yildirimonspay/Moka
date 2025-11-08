using System.ComponentModel.DataAnnotations;

namespace Moka.Simulator.Models;

public class PaymentDealerAuthentication
{
[Required]
    public string? DealerCode { get; set; }

    [Required]
    public string? Username { get; set; }

    [Required]
    public string? Password { get; set; }

    public string? CheckKey { get; set; }
}
