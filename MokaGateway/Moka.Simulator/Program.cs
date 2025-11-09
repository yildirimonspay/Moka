using Microsoft.EntityFrameworkCore;
using Moka.Simulator.Data;
using Moka.Simulator.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
// HttpClient for calling Moka.Api or external endpoints
builder.Services.AddHttpClient();
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
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapHealthChecks("/health");
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
