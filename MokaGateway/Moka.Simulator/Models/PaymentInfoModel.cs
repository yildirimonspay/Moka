using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace Moka.Simulator.Models;

public class PaymentInfoModel : IValidatableObject
{
    public PaymentInfoModel()
    {
        CreditCardTypes = new List<SelectListItem>();
        ExpireMonths = new List<SelectListItem>();
    ExpireYears = new List<SelectListItem>();
    }

    [Display(Name = "Credit Card Type")]
    public string? CreditCardType { get; set; }

    public IList<SelectListItem> CreditCardTypes { get; set; }

    [Required, Display(Name = "Cardholder Name")]
    public string? CardholderName { get; set; }

    [Required, CreditCard, Display(Name = "Card Number")]
    public string? CardNumber { get; set; }

    [Required, Display(Name = "Expire Month")]
public string? ExpireMonth { get; set; }

    [Required, Display(Name = "Expire Year")]
    public string? ExpireYear { get; set; }

    public IList<SelectListItem> ExpireMonths { get; set; }

    public IList<SelectListItem> ExpireYears { get; set; }

    [Required, RegularExpression("^[0-9]{3,4}$", ErrorMessage = "Invalid CVC")]
    [Display(Name = "CVC")]
    public string? CardCode { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
    if (!int.TryParse(ExpireMonth, out var m) || m < 1 || m > 12)
        yield return new ValidationResult("Expiration month must be between 1 and 12", new[] { nameof(ExpireMonth) });

   if (!int.TryParse(ExpireYear, out var y))
        yield return new ValidationResult("Expiration year is invalid", new[] { nameof(ExpireYear) });
    else
    {
        if (y < 100) y += 2000; // normalize two-digit year
   var entered = new DateTime(y, Math.Clamp(m, 1, 12), 1).AddMonths(1);
  if (entered < DateTime.UtcNow)
      yield return new ValidationResult("Card is expired", new[] { nameof(ExpireMonth), nameof(ExpireYear) });
        }
    }
}
