namespace Moka.Contracts.Settings;

public class MokaSettings
{
 public string? Mode { get; set; }
 public string? DealerCode { get; set; }
 public string? Username { get; set; }
 public string? Password { get; set; }
 public string? PostUrl { get; set; }
 public string? RedirectUrl { get; set; }
 public string? NotifyUrl { get; set; }
 public string[]? AllowedIps { get; set; }
 // New flags / lists for spec validations
 public bool AllowPoolPayments { get; set; } = false;
 public bool ForcePoolPayments { get; set; } = false;
 public bool AllowPreAuth { get; set; } = false;
 public bool AllowTokenization { get; set; } = false;
 public int MaxInstallment { get; set; } =12;
 public int MaxInstallmentPerVirtualPos { get; set; } =6;
 public bool RequireCommissionForInstallments { get; set; } = false;
 public string[]? AllowedCurrencies { get; set; } = new[] { "TL", "USD", "EUR", "GBP" };
 public string[]? ForeignCurrenciesEnabled { get; set; } = new[] { "USD", "EUR" }; // subset dealer allowed
 public string[]? AllowedBins { get; set; } = new[] { "4", "5" }; // simple BIN prefixes
 public string[]? AllowedSubMerchants { get; set; }
 public string[]? AllowedSoftware { get; set; }
 public string[]? KnownProductCodes { get; set; }
 public decimal DailyDealerLimit { get; set; } =100000m; // TL
 public decimal DailyCardLimit { get; set; } =50000m; // TL per BIN
 // RedirectUrl security
 public string[]? RedirectDomainWhitelist { get; set; }
 public string? RedirectHmacSecret { get; set; }
}
