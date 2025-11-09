using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations;

namespace Moka.Simulator.Models;

public class DealerPaymentInputModel : IValidatableObject
{
    // Card info
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

    // Payment basics
    [Range(0.01, double.MaxValue)]
    [Display(Name = "Amount")]
    public decimal Amount { get; set; } = 100.99m;

    [Display(Name = "Installments")]
    [Range(1, 12)]
    public int InstallmentNumber { get; set; } = 1;

    // UI lists
    public IList<SelectListItem> ExpireMonths { get; set; } = new List<SelectListItem>();
    public IList<SelectListItem> ExpireYears { get; set; } = new List<SelectListItem>();

    // Added for passing data to redirect view
    public List<TestCard> TestCards { get; set; } = new();
    public string? PostUrl { get; set; }
    public string? Trx { get; set; }
    public string? Hash { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!int.TryParse(ExpMonth, out var m) || m < 1 || m > 12)
            yield return new ValidationResult("Expiration month must be between 1 and 12", new[] { nameof(ExpMonth) });

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
