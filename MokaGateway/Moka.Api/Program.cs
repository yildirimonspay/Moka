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

// EF Core - SQL Server (MokaContext)
builder.Services.AddDbContext<Moka.Api.Data.MokaDbContext>(opt =>
{
 var cs = builder.Configuration.GetConnectionString("MokaContext")
 ?? "Server=.;Database=MokaGateway;Trusted_Connection=True;TrustServerCertificate=True;";
 opt.UseSqlServer(cs);
});

// Bind settings
builder.Services.Configure<Moka.Contracts.Settings.MokaSettings>(builder.Configuration.GetSection("Moka"));

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
 c.SwaggerDoc("v1", new() { Title = "Moka.Api", Version = "v1" });
 c.AddSecurityDefinition("ApiKey", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
 {
 Name = "X-API-KEY",
 Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
 In = Microsoft.OpenApi.Models.ParameterLocation.Header,
 Description = "Provide the API key"
 });
 c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
 {
 { new Microsoft.OpenApi.Models.OpenApiSecurityScheme { Reference = new Microsoft.OpenApi.Models.OpenApiReference { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "ApiKey" } }, Array.Empty<string>() }
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
 try { db.Database.Migrate(); Log.Information("DB migration completed"); }
 catch { db.Database.EnsureCreated(); Log.Information("DB ensured created"); }
}

if (app.Environment.IsDevelopment())
{
 app.UseSwagger();
 app.UseSwaggerUI(c =>
 {
 c.DisplayOperationId();
 c.DocumentTitle = "Moka.Api";
 });
}

// Push RequestPath into Serilog context
app.Use(async (ctx, next) =>
{
 using (Serilog.Context.LogContext.PushProperty("RequestPath", ctx.Request.Path.Value))
 {
 await next();
 }
});

// Emit request logs (Info by default)
app.UseSerilogRequestLogging();

app.UseHttpsRedirection();
// Global API Key auth
app.UseMiddleware<Moka.Api.Middleware.ApiKeyMiddleware>();
app.UseAuthorization();
app.MapHealthChecks("/health");
app.MapControllers();

Log.Information("Moka.Api started");

app.Run();
