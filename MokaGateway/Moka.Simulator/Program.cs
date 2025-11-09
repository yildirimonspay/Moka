var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
// HttpClient for calling Moka.Api or external endpoints
builder.Services.AddHttpClient();
// Bind Moka settings
builder.Services.Configure<Moka.Contracts.Settings.MokaSettings>(builder.Configuration.GetSection("Moka"));
// In-memory cache to keep transient transaction data (e.g., CodeForHash)
builder.Services.AddMemoryCache();
// Order service
builder.Services.AddSingleton<Moka.Simulator.Services.IOrderService, Moka.Simulator.Services.OrderService>();
// Payment query service - typed HttpClient
builder.Services.AddHttpClient<Moka.Simulator.Services.PaymentQueryService>();
builder.Services.AddTransient<Moka.Simulator.Services.IPaymentQueryService>(sp => sp.GetRequiredService<Moka.Simulator.Services.PaymentQueryService>());
// Health checks
builder.Services.AddHealthChecks();
// Compression
builder.Services.AddResponseCompression();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
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
