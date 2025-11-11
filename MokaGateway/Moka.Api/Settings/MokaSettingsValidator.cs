using Microsoft.Extensions.Options;
using Moka.Contracts.Settings;

namespace Moka.Api.Settings;

public class MokaSettingsValidator : IValidateOptions<MokaSettings>
{
 public ValidateOptionsResult Validate(string? name, MokaSettings options)
 {
 var failures = new List<string>();
 if (string.IsNullOrWhiteSpace(options.DealerCode)) failures.Add("DealerCode missing");
 if (string.IsNullOrWhiteSpace(options.Username)) failures.Add("Username missing");
 if (string.IsNullOrWhiteSpace(options.Password)) failures.Add("Password missing");
 if (options.RedirectDomainWhitelist is null && (options.RedirectDomainsPerDealer is null || options.RedirectDomainsPerDealer.Count ==0))
 failures.Add("Redirect domain whitelist not configured");
 if (string.IsNullOrWhiteSpace(options.RedirectHmacSecret)) failures.Add("RedirectHmacSecret missing (HMAC signatures disabled)");
 if (failures.Count>0) return ValidateOptionsResult.Fail(failures);
 return ValidateOptionsResult.Success;
 }
}