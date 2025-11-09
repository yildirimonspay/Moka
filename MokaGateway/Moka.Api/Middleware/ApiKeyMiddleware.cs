using System.Threading.Tasks;
namespace Moka.Api.Middleware;

public class ApiKeyMiddleware
{
    private readonly RequestDelegate _next;
    private const string HeaderName = "X-API-KEY";
    public ApiKeyMiddleware(RequestDelegate next) => _next = next;
    public async Task InvokeAsync(HttpContext context)
    {
        // Allow health & swagger without key
        var path = context.Request.Path.Value?.ToLowerInvariant();
        if (path != null && (path.StartsWith("/health") || path.StartsWith("/swagger")))
        {
            await _next(context); return;
        }
        if (!context.Request.Headers.TryGetValue(HeaderName, out var provided))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { error = "API key missing" });
            return;
        }
        var configured = context.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("ApiKeys:Primary");
        if (string.IsNullOrWhiteSpace(configured) || !string.Equals(configured, provided, StringComparison.Ordinal))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(new { error = "API key invalid" });
            return;
        }
        await _next(context);
    }
}

public static class ApiKeyMiddlewareExtensions
{
    public static IApplicationBuilder UseApiKeyAuth(this IApplicationBuilder app) => app.UseMiddleware<ApiKeyMiddleware>();
}
