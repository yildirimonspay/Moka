using Microsoft.EntityFrameworkCore;

namespace Moka.Api.Middleware;

public class ApiKeyMiddleware
{
    private readonly RequestDelegate _next;
    private const string HeaderName = "X-API-KEY";
    private static string[] _publicPatterns = new[]
    {
        "/paymentdealer/paymentdealerthreedprocess", //3D page GET/POST
        "/paymentdealer/bankauthorizationcallback" // bank callback POST
    };
    public ApiKeyMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        var path = (context.Request.Path.Value ?? string.Empty);
        // Allow health & swagger without key
        if (StartsWith(path, "/health") || StartsWith(path, "/swagger"))
        { 
            await _next(context); 
            return; 
        }

        // Allow static files (wwwroot) and razor assets
        if (StartsWith(path, "/css") || StartsWith(path, "/js") || StartsWith(path, "/lib") || StartsWith(path, "/favicon"))
        { 
            await _next(context); 
            return; 
        }

        // Preflight (CORS) or HEAD requests do not require auth
        if (string.Equals(context.Request.Method, "OPTIONS", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(context.Request.Method, "HEAD", StringComparison.OrdinalIgnoreCase))
        { 
            await _next(context); 
            return; 
        }

        // Config override for public patterns
        var cfg = context.RequestServices.GetRequiredService<IConfiguration>();
        var cfgPublic = cfg.GetSection("ApiKeys:PublicPaths").Get<string[]>() ?? Array.Empty<string>();
        if (cfgPublic.Length >0) 
            _publicPatterns = cfgPublic.Select(p => p.ToLowerInvariant()).ToArray();

        // If API key provided, validate normally
        if (context.Request.Headers.TryGetValue(HeaderName, out var provided))
        {
            var configured = cfg.GetValue<string>("ApiKeys:Primary");
            if (!string.IsNullOrWhiteSpace(configured) && string.Equals(configured, provided, StringComparison.Ordinal))
            { 
                await _next(context); 
                return; 
            }
            await WriteError(context,401, "API key invalid");
            return;
        }

        // No API key: attempt contextual auth only if path is a public pattern
        if (_publicPatterns.Any(p => StartsWith(path, p)))
        {
            bool allowed = false;
            try
            {
                var db = context.RequestServices.GetRequiredService<Moka.Api.Data.MokaDbContext>();
                if (StartsWith(path, "/paymentdealer/paymentdealerthreedprocess"))
                {
                    // GET or POST3D page: require valid threeDTrxCode that exists and not expired
                    string threeD = context.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                        ? context.Request.Form["threeDTrxCode"].FirstOrDefault()
                        : context.Request.Query["threeDTrxCode"].FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(threeD))
                    {
                        var entity = await db.Payments.AsNoTracking().FirstOrDefaultAsync(p => p.ThreeDTrxCode == threeD);
                        if (entity != null && (entity.Status == "Pending3D" || entity.Status == "OtpVerified"))
                            allowed = true; // still in3D flow
                    }
                }
                else if (StartsWith(path, "/paymentdealer/bankauthorizationcallback"))
                {
                    // Bank callback: must have threeDTrxCode and entity status OtpVerified (already passed OTP)
                    string threeD = context.Request.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                        ? context.Request.Form["threeDTrxCode"].FirstOrDefault()
                        : context.Request.Query["threeDTrxCode"].FirstOrDefault();
                    if (!string.IsNullOrWhiteSpace(threeD))
                    {
                        var entity = await db.Payments.AsNoTracking().FirstOrDefaultAsync(p => p.ThreeDTrxCode == threeD);
                        if (entity != null && entity.Status == "OtpVerified")
                        {
                            // optional bank secret check
                            var bankSecretConfigured = cfg.GetValue<string>("ApiKeys:BankCallbackSecret");
                            if (string.IsNullOrWhiteSpace(bankSecretConfigured)) 
                                allowed = true; // no secret configured
                            else {
                                var supplied = context.Request.Form["bankSecret"].FirstOrDefault() ?? context.Request.Headers["X-BANK-SECRET"].FirstOrDefault();
                                if (!string.IsNullOrWhiteSpace(supplied) && string.Equals(supplied, bankSecretConfigured, StringComparison.Ordinal)) 
                                    allowed = true; 
                            }
                        }
                    }
                }
            }
            catch { /* ignore */ }
            if (allowed) { await _next(context); return; }
        }

        // Reject
        await WriteError(context,401, "API key missing");
    }

    private static bool StartsWith(string path, string prefix) => path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    private static async Task WriteError(HttpContext ctx, int code, string message)
    {
        ctx.Response.StatusCode = code;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsJsonAsync(new { error = message });
    }
}

public static class ApiKeyMiddlewareExtensions
{
    public static IApplicationBuilder UseApiKeyAuth(this IApplicationBuilder app) => app.UseMiddleware<ApiKeyMiddleware>();
}
