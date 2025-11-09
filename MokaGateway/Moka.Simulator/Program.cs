using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
// HttpClient for calling Moka.Api or external endpoints
builder.Services.AddHttpClient();
// Bind Moka settings
builder.Services.Configure<Moka.Contracts.Settings.MokaSettings>(builder.Configuration.GetSection("Moka"));
// Compression
builder.Services.AddResponseCompression();
// Order service
builder.Services.AddSingleton<Moka.Simulator.Services.IOrderService, Moka.Simulator.Services.OrderService>();
// Payment query service - typed HttpClient
builder.Services.AddHttpClient<Moka.Simulator.Services.PaymentQueryService>();
builder.Services.AddTransient<Moka.Simulator.Services.IPaymentQueryService>(sp => sp.GetRequiredService<Moka.Simulator.Services.PaymentQueryService>());
// Health checks
builder.Services.AddHealthChecks();
builder.Services.AddDbContext<Moka.Simulator.Data.SimulatorDbContext>(opt =>
{
    var cs = builder.Configuration.GetConnectionString("MokaContext") ?? "Server=.;Database=MokaGateway;Trusted_Connection=True;TrustServerCertificate=True;";
    opt.UseSqlServer(cs);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<Moka.Simulator.Data.SimulatorDbContext>();
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
