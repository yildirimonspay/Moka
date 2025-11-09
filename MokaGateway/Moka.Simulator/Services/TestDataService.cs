using System.Text.Json;
using Moka.Simulator.Models;

namespace Moka.Simulator.Services;

public class TestDataService : ITestDataService
{
 private readonly IWebHostEnvironment _env;
 private readonly ILogger<TestDataService> _logger;
 private readonly Lazy<TestDataPayload> _data;

 public TestDataService(IWebHostEnvironment env, ILogger<TestDataService> logger)
 {
 _env = env;
 _logger = logger;
 _data = new Lazy<TestDataPayload>(Load);
 }

 public List<TestCard> GetTestCards() => _data.Value.Cards;
 public string GetErrorMessage(string? code)
 {
 if (string.IsNullOrWhiteSpace(code)) return _data.Value.DefaultError;
 return _data.Value.Errors.TryGetValue(code, out var msg) ? msg : _data.Value.DefaultError;
 }

 private TestDataPayload Load()
 {
 try
 {
 var path = Path.Combine(_env.ContentRootPath, "App_Data", "testdata.json");
 if (!File.Exists(path)) return new TestDataPayload();
 var json = File.ReadAllText(path);
 var payload = JsonSerializer.Deserialize<TestDataPayload>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new TestDataPayload();
 return payload;
 }
 catch (Exception ex)
 {
 _logger.LogError(ex, "Failed loading test data json");
 return new TestDataPayload();
 }
 }
}

public class TestDataPayload
{
 public List<TestCard> Cards { get; set; } = new();
 public Dictionary<string, string> Errors { get; set; } = new();
 public string DefaultError { get; set; } = "Ýþleminizi gerçekleþtiremiyoruz. Kredi kartý bilgilerinizi kontrol ettikten sonra tekrar deneyiniz.";
}
