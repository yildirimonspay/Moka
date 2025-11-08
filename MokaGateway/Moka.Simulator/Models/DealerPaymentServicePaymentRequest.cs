using System.ComponentModel.DataAnnotations;

namespace Moka.Simulator.Models;

public class DealerPaymentServicePaymentRequest
{
    [Required]
public PaymentDealerAuthentication PaymentDealerAuthentication { get; set; } = new();

    [Required]
    public PaymentDealerRequest PaymentDealerRequest { get; set; } = new();
}
