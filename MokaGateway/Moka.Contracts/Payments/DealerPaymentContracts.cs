using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

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
    [Required] public string? DealerCode { get; set; }
    [Required] public string? Username { get; set; }
    [Required] public string? Password { get; set; }
    public string? CheckKey { get; set; }
}

public class PaymentDealerRequest : IValidatableObject
{
    [Required] public string? CardHolderFullName { get; set; }
    // Either CardNumber or CardToken required (if tokenization)
    public string? CardNumber { get; set; }
    public string? CardToken { get; set; }
    [Required] public string? ExpMonth { get; set; }
    [Required] public string? ExpYear { get; set; }
    [Required] public string? CvcNumber { get; set; }
    [Range(0.01, double.MaxValue)] public decimal Amount { get; set; }
    public string? Currency { get; set; } // TL, USD, EUR, GBP
    [Range(0,12)] public int InstallmentNumber { get; set; }
    public string? OtherTrxCode { get; set; }
    public string? ClientIP { get; set; }
    public string? RedirectUrl { get; set; }
    public int ReturnHash { get; set; } =1;
    // Flags
    public int IsPoolPayment { get; set; } //0/1
    public int IsPreAuth { get; set; } //0/1
    public int IsTokenized { get; set; } //0/1
    public int IntegratorId { get; set; }
    public string? Software { get; set; }
    public string? Description { get; set; }
    public int RedirectType { get; set; }
    public BuyerInformation? BuyerInformation { get; set; }
    public CustomerInformation? CustomerInformation { get; set; }
    public List<BasketProduct>? BasketProducts { get; set; }
    // New fields for remaining spec
    public string? SubMerchantName { get; set; }
    public int? VirtualPosId { get; set; }
    public decimal? CommissionRate { get; set; }
    public decimal? GroupCommissionRate { get; set; }
    public decimal? DailyDealerTotal { get; set; }
    public decimal? DailyDealerLimit { get; set; }
    public decimal? DailyCardTotal { get; set; }
    public decimal? DailyCardLimit { get; set; }
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        // Card/token exclusivity
        if (string.IsNullOrWhiteSpace(CardNumber) && string.IsNullOrWhiteSpace(CardToken))
            yield return new ValidationResult("Either CardNumber or CardToken must be provided", new[] { nameof(CardNumber), nameof(CardToken) });
        if (!string.IsNullOrWhiteSpace(CardNumber) && !string.IsNullOrWhiteSpace(CardToken))
            yield return new ValidationResult("Provide only CardNumber or CardToken, not both", new[] { nameof(CardNumber), nameof(CardToken) });
        // Luhn validation if card present
        if (!string.IsNullOrWhiteSpace(CardNumber) && !IsValidLuhn(CardNumber))
            yield return new ValidationResult("PaymentDealer.CheckCardInfo.InvalidCardInfo", new[] { nameof(CardNumber) });
        // Currency whitelist
        if (!string.IsNullOrWhiteSpace(Currency))
        {
            var allowed = new[] { "TL", "USD", "EUR", "GBP" };
            if (!allowed.Contains(Currency))
                yield return new ValidationResult("PaymentDealer.DoDirectPayment3dRequest.InvalidCurrencyCode", new[] { nameof(Currency) });
        }
        // Installment rules:0 or1 => cash; >1 must be between2-12
        if (InstallmentNumber <0 || InstallmentNumber >12)
            yield return new ValidationResult("PaymentDealer.DoDirectPayment3dRequest.InvalidInstallmentNumber", new[] { nameof(InstallmentNumber) });
        // Basket consistency
        if (BasketProducts?.Count >0)
        {
            var basketAmount = BasketProducts.Sum(b => b.UnitPrice * b.Quantity);
            if (basketAmount != Amount)
                yield return new ValidationResult("PaymentDealer.DoDirectPayment3dRequest.BasketAmountIsNotEqualPaymentAmount", new[] { nameof(BasketProducts) });
            foreach (var p in BasketProducts)
            {
                if (p.UnitPrice <=0) yield return new ValidationResult("PaymentDealer.DoDirectPayment3dRequest.InvalidUnitPrice", new[] { nameof(BasketProducts) });
                if (p.Quantity <=0) yield return new ValidationResult("PaymentDealer.DoDirectPayment3dRequest.InvalidQuantityValue", new[] { nameof(BasketProducts) });
            }
        }
        // Daily limits
        if (DailyDealerLimit.HasValue && DailyDealerTotal.HasValue && DailyDealerTotal.Value > DailyDealerLimit.Value)
            yield return new ValidationResult("PaymentDealer.CheckDealerPaymentLimits.DailyDealerLimitExceeded", new[] { nameof(DailyDealerTotal) });
        if (DailyCardLimit.HasValue && DailyCardTotal.HasValue && DailyCardTotal.Value > DailyCardLimit.Value)
            yield return new ValidationResult("PaymentDealer.CheckDealerPaymentLimits.DailyCardLimitExceeded", new[] { nameof(DailyCardTotal) });
        // Commission presence if VirtualPos used
        if (VirtualPosId.HasValue && InstallmentNumber>0 && !CommissionRate.HasValue)
            yield return new ValidationResult("PaymentDealer.DoDirectPayment3dRequest.DealerCommissionRateNotFound", new[] { nameof(CommissionRate) });
        if (VirtualPosId.HasValue && InstallmentNumber>0 && !GroupCommissionRate.HasValue)
            yield return new ValidationResult("PaymentDealer.DoDirectPayment3dRequest.DealerGroupCommissionRateNotFound", new[] { nameof(GroupCommissionRate) });
        // SubMerchantName presence (simulate registry) if provided but malformed
        if (!string.IsNullOrWhiteSpace(SubMerchantName) && SubMerchantName.Length <3)
            yield return new ValidationResult("PaymentDealer.DoDirectPayment3dRequest.InvalidSubMerchantName", new[] { nameof(SubMerchantName) });
    }

    private bool IsValidLuhn(string num)
    {
        var digits = Regex.Replace(num, "[^0-9]", "");
        int sum =0; bool alt = false;
        for (int i = digits.Length -1; i >=0; i--)
        {
            int d = digits[i] - '0';
            if (alt) { d *=2; if (d >9) d -=9; }
            sum += d; alt = !alt;
        }
        return sum %10 ==0;
    }
}

public class BuyerInformation
{
    public string? BuyerFullName { get; set; }
    public string? BuyerEmail { get; set; }
    public string? BuyerGsmNumber { get; set; }
    public string? BuyerAddress { get; set; }
}

public class CustomerInformation
{
    public string? DealerCustomerId { get; set; }
    public string? CustomerCode { get; set; }
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Gender { get; set; }
    public string? BirthDate { get; set; }
    public string? GsmNumber { get; set; }
    public string? Email { get; set; }
    public string? Address { get; set; }
    public string? CardName { get; set; }
}

public class BasketProduct
{
    public int ProductId { get; set; }
    public string? ProductCode { get; set; }
    public int Quantity { get; set; }
    public decimal UnitPrice { get; set; }
}
