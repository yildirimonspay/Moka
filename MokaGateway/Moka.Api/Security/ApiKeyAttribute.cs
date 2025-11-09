using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Moka.Api.Security;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class ApiKeyAttribute : Attribute, IAsyncActionFilter
{
 private const string HeaderName = "X-API-KEY";
 public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
 {
 if (!context.HttpContext.Request.Headers.TryGetValue(HeaderName, out var provided))
 {
 context.Result = new UnauthorizedObjectResult(new { error = "API key missing" });
 return;
 }
 var configured = context.HttpContext.RequestServices.GetRequiredService<IConfiguration>().GetValue<string>("ApiKeys:Primary");
 if (string.IsNullOrWhiteSpace(configured) || !string.Equals(configured, provided, StringComparison.Ordinal))
 {
 context.Result = new UnauthorizedObjectResult(new { error = "API key invalid" });
 return;
 }
 await next();
 }
}
