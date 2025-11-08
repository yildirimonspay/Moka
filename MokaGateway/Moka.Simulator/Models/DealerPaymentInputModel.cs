using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace Moka.Simulator.Models;

public class DealerPaymentInputModel : IValidatableObject
{
    // Auth
    [Required]
    [Display(Name = "Dealer Code")]
    public string? DealerCode { get; set; }

    [Required]
    [Display(Name = "Username")]
    public string? Username { get; set; }

    [Required]
    [Display(Name = "Password")]
    public string? Password { get; set; }

    [Display(Name = "Check Key")]
    public string? CheckKey { get; set; }

    // Payment
    [Required]
    [Display(Name = "Cardholder Name")]
    public string? CardHolderFullName { get; set; }

    [Required, CreditCard]
    [Display(Name = "Card Number")]
    public string? CardNumber { get; set; }

    [Required]
    [Display(Name = "Expire Month")]
    public string? ExpMonth { get; set; }

    [Required]
    [Display(Name = "Expire Year")]
    public string? ExpYear { get; set; }

    [Required]
    [RegularExpression("^[0-9]{3,4}$")]
    [Display(Name = "CVC")]
    public string? CvcNumber { get; set; }

    [Range(0.01, double.MaxValue)]
    [Display(Name = "Amount")]
    public decimal Amount { get; set; }

    [Display(Name = "Currency")]
    public string? Currency { get; set; } = "TRY";

    [Display(Name = "Installments")]
    public int InstallmentNumber { get; set; } = 1;

    [Display(Name = "Order Id")]
    public string? VirtualPosOrderId { get; set; }

    [Display(Name = "Other Trx Code")]
    public string? OtherTrxCode { get; set; }

    [Display(Name = "Void/Refund Reason")]
    public int VoidRefundReason { get; set; }

    [Display(Name = "Client IP")]
    public string? ClientIP { get; set; }

    [Display(Name = "Redirect Url")]
    public string? RedirectUrl { get; set; }

    public IList<SelectListItem> ExpireMonths { get; set; } = new List<SelectListItem>();
    public IList<SelectListItem> ExpireYears { get; set; } = new List<SelectListItem>();

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!int.TryParse(ExpMonth, out var m) || m < 1 || m > 12)
            yield return new ValidationResult("Expiration month must be between1 and12", new[] { nameof(ExpMonth) });

        if (!int.TryParse(ExpYear, out var y))
            yield return new ValidationResult("Expiration year is invalid", new[] { nameof(ExpYear) });
        else
        {
            if (y < 100) y += 2000; // normalize two-digit year
            var entered = new DateTime(y, Math.Clamp(m, 1, 12), 1).AddMonths(1);
            if (entered < DateTime.UtcNow)
                yield return new ValidationResult("Card is expired", new[] { nameof(ExpMonth), nameof(ExpYear) });
        }
    }
}
