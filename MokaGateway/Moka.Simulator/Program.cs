using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using System.Threading.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Moka.Simulator.Data;
using Moka.Simulator.Services;

var builder = WebApplication.CreateBuilder(args);

// Kestrel hardening
builder.WebHost.ConfigureKestrel(opt =>
{
    opt.AddServerHeader = false;
    opt.Limits.MaxRequestBodySize = 1 * 1024 * 1024; //1 MB
    opt.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(30);
    opt.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(15);
});

// Add services to the container.
builder.Services.AddControllersWithViews(options =>
{
        options.MaxModelBindingCollectionSize = 64;
    })
    .AddRazorRuntimeCompilation();// HttpClient for calling Moka.Api or external endpoints
builder.Services.AddHttpClient();
// Forwarded headers (behind proxy)
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});
// Rate limiting
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    options.AddPolicy("gateway", httpContext =>
    {
        var key = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetTokenBucketLimiter(key, _ => new TokenBucketRateLimiterOptions
        {
            TokenLimit = 20,
            TokensPerPeriod = 20,
            ReplenishmentPeriod = TimeSpan.FromSeconds(10),
            AutoReplenishment = true,
            QueueLimit = 0,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst
        });
    });
});
// Bind Moka settings
builder.Services.Configure<Moka.Contracts.Settings.MokaSettings>(builder.Configuration.GetSection("Moka"));
// Compression
builder.Services.AddResponseCompression();
// Test data service
builder.Services.AddSingleton<ITestDataService, TestDataService>();
// Order service
builder.Services.AddSingleton<IOrderService, OrderService>();
// Payment query service - typed HttpClient
builder.Services.AddHttpClient<PaymentQueryService>();
builder.Services.AddTransient<IPaymentQueryService>(sp => sp.GetRequiredService<PaymentQueryService>());
// Health checks
builder.Services.AddHealthChecks();
builder.Services.AddDbContext<SimulatorDbContext>(opt =>
{
    var cs = builder.Configuration.GetConnectionString("MokaContext") ?? "Server=.;Database=MokaGateway;Trusted_Connection=True;TrustServerCertificate=True;";
    opt.UseSqlServer(cs);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<SimulatorDbContext>();
    try { db.Database.Migrate(); }
    catch { db.Database.EnsureCreated(); }
}

app.UseResponseCompression();
app.UseForwardedHeaders();
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseRateLimiter();

// Basic security headers
app.Use(async (ctx, next) =>
{
    await next();
    ctx.Response.Headers.TryAdd("X-Content-Type-Options", "nosniff");
    ctx.Response.Headers.TryAdd("Referrer-Policy", "no-referrer");
    ctx.Response.Headers.TryAdd("X-Frame-Options", "DENY");
});

app.UseAuthorization();

app.MapHealthChecks("/health");
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=DealerPayment}/{action=Create}/{id?}");

app.Run();
