using Microsoft.EntityFrameworkCore;
using Serilog;
using Swashbuckle.AspNetCore.Filters;

var builder = WebApplication.CreateBuilder(args);

// Serilog
Log.Logger = new LoggerConfiguration()
 .ReadFrom.Configuration(builder.Configuration)
 .Enrich.FromLogContext()
 .WriteTo.Console()
 .CreateLogger();
builder.Host.UseSerilog();

// EF Core - Sqlite
builder.Services.AddDbContext<Moka.Api.Data.MokaDbContext>(opt =>
{
 var cs = builder.Configuration.GetConnectionString("MokaDb") ?? "Data Source=moka.db";
 opt.UseSqlite(cs);
});

// Bind settings
builder.Services.Configure<Moka.Contracts.Settings.MokaSettings>(builder.Configuration.GetSection("Moka"));

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
 c.SwaggerDoc("v1", new() { Title = "Moka.Api", Version = "v1" });
 // Simple header auth example
 c.AddSecurityDefinition("ApiKey", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
 {
 Name = "X-API-KEY",
 Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
 In = Microsoft.OpenApi.Models.ParameterLocation.Header,
 Description = "Demo API key"
 });
 c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
 {
 {
 new Microsoft.OpenApi.Models.OpenApiSecurityScheme { Reference = new Microsoft.OpenApi.Models.OpenApiReference { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "ApiKey" } },
 Array.Empty<string>()
 }
 });
 c.ExampleFilters();
});
// Swagger examples provider
builder.Services.AddSwaggerExamplesFromAssemblyOf<Moka.Api.Swagger.DealerPaymentExample>();

// Health checks
builder.Services.AddHealthChecks();

var app = builder.Build();

// Apply database
using (var scope = app.Services.CreateScope())
{
 var db = scope.ServiceProvider.GetRequiredService<Moka.Api.Data.MokaDbContext>();
 try { db.Database.Migrate(); }
 catch { db.Database.EnsureCreated(); }
}

if (app.Environment.IsDevelopment())
{
 app.UseSwagger();
 app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapHealthChecks("/health");
app.MapControllers();

app.Run();
