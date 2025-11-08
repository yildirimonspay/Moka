using System.ComponentModel.DataAnnotations;

namespace Moka.Simulator.Models;

public class PaymentDealerRequest
{
    [Required]
    public string? CardHolderFullName { get; set; }

    [Required, CreditCard]
    public string? CardNumber { get; set; }

    [Required]
    [RegularExpression("^(0?[1-9]|1[0-2])$", ErrorMessage = "Invalid month (1-12)")]
    public string? ExpMonth { get; set; }

    [Required]
    [RegularExpression("^\\d{2,4}$", ErrorMessage = "Invalid year")]
public string? ExpYear { get; set; }

    [Required]
[RegularExpression("^[0-9]{3,4}$", ErrorMessage = "Invalid CVC")]
public string? CvcNumber { get; set; }

    [Range(0.01, double.MaxValue)]
    public decimal Amount { get; set; }

    public string? Currency { get; set; }

    public int InstallmentNumber { get; set; }

    public string? VirtualPosOrderId { get; set; }

    public string? OtherTrxCode { get; set; }

    public int VoidRefundReason { get; set; }

    public string? ClientIP { get; set; }

    public string? RedirectUrl { get; set; }

public int UtilityCompanyBillId { get; set; }

    public int DealerStaffId { get; set; }

    public int ReturnHash { get; set; }
}
