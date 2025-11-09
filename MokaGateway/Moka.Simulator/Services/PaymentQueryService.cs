using System.Text.Json;
using Moka.Contracts.Settings;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace Moka.Simulator.Services;

public record PaymentItem(string OtherTrxCode, string TrxCode, decimal Amount, string Currency, string Status, DateTime CreatedUtc);
public record PaymentDetail(string OtherTrxCode, string TrxCode, string CodeForHash, decimal Amount, string Currency, string Status, DateTime CreatedUtc);

public interface IPaymentQueryService
{
 Task<IReadOnlyList<PaymentItem>> GetPaymentsAsync(CancellationToken ct = default);
 Task<PaymentDetail?> GetByOtherAsync(string otherTrxCode, CancellationToken ct = default);
 Task<PaymentDetail?> GetByTrxAsync(string trxCode, CancellationToken ct = default);
}

public class PaymentQueryService : IPaymentQueryService
{
 private readonly HttpClient _httpClient;
 private readonly MokaSettings _settings;
 private readonly IConfiguration _config;
 private readonly ILogger<PaymentQueryService> _logger;
 private static readonly JsonSerializerOptions _jsonOpts = new() { PropertyNameCaseInsensitive = true };
 private volatile bool _baseConfigured;

 public PaymentQueryService(HttpClient httpClient, IOptions<MokaSettings> settings, IConfiguration config, ILogger<PaymentQueryService> logger)
 {
 _httpClient = httpClient;
 _settings = settings.Value;
 _config = config;
 _logger = logger;
 }

 private void EnsureBaseUrl()
 {
 if (_baseConfigured) return;
 var postUrl = _settings.PostUrl ?? _config["Moka:PostUrl"] ?? throw new InvalidOperationException("Moka:PostUrl is not configured");
 string baseUrl;
 if (postUrl.EndsWith("/pay", StringComparison.OrdinalIgnoreCase))
 baseUrl = postUrl[..^"/pay".Length];
 else
 baseUrl = postUrl.TrimEnd('/');
 _httpClient.BaseAddress = new Uri(baseUrl + "/");
 _baseConfigured = true;
 }

 private async Task<T?> GetWithRetryAsync<T>(string relative, CancellationToken ct)
 {
 EnsureBaseUrl();
 const int maxAttempts =3;
 for (var attempt =1; attempt <= maxAttempts; attempt++)
 {
 try
 {
 using var resp = await _httpClient.GetAsync(relative, ct);
 if (!resp.IsSuccessStatusCode)
 {
 _logger.LogWarning("Payment query {Relative} failed with status {Status} (attempt {Attempt}/{Max})", relative, resp.StatusCode, attempt, maxAttempts);
 if (attempt == maxAttempts) return default;
 await Task.Delay(TimeSpan.FromMilliseconds(200 * attempt), ct);
 continue;
 }
 var stream = await resp.Content.ReadAsStreamAsync(ct);
 return await JsonSerializer.DeserializeAsync<T>(stream, _jsonOpts, ct);
 }
 catch (OperationCanceledException) when (ct.IsCancellationRequested)
 {
 _logger.LogInformation("Payment query {Relative} canceled", relative);
 return default;
 }
 catch (Exception ex) when (attempt < maxAttempts)
 {
 _logger.LogWarning(ex, "Transient error querying {Relative} attempt {Attempt}/{Max}", relative, attempt, maxAttempts);
 await Task.Delay(TimeSpan.FromMilliseconds(200 * attempt), ct);
 }
 catch (Exception ex)
 {
 _logger.LogError(ex, "Payment query {Relative} failed after {Attempts} attempts", relative, maxAttempts);
 return default;
 }
 }
 return default;
 }

 public async Task<IReadOnlyList<PaymentItem>> GetPaymentsAsync(CancellationToken ct = default)
 {
 var data = await GetWithRetryAsync<List<PaymentItem>>("payments", ct);
 if (data is null) return Array.Empty<PaymentItem>();
 return data;
 }

 public Task<PaymentDetail?> GetByOtherAsync(string otherTrxCode, CancellationToken ct = default)
 => GetWithRetryAsync<PaymentDetail>($"payments/other/{Uri.EscapeDataString(otherTrxCode)}", ct);

 public Task<PaymentDetail?> GetByTrxAsync(string trxCode, CancellationToken ct = default)
 => GetWithRetryAsync<PaymentDetail>($"payments/trx/{Uri.EscapeDataString(trxCode)}", ct);
}
