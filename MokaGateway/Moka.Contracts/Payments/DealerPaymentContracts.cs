using System.ComponentModel.DataAnnotations;

namespace Moka.Contracts.Payments;

public class DealerPaymentServicePaymentRequest
{
    [Required]
    public PaymentDealerAuthentication PaymentDealerAuthentication { get; set; } = new();
    [Required]
    public PaymentDealerRequest PaymentDealerRequest { get; set; } = new();
}

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

public class PaymentDealerRequest
{
    [Required]
    public string? CardHolderFullName { get; set; }
    [Required]
    public string? CardNumber { get; set; }
    [Required]
    public string? ExpMonth { get; set; }
    [Required]
    public string? ExpYear { get; set; }
    [Required]
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
