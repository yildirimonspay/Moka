using Microsoft.AspNetCore.Mvc;
using Moka.Simulator.Services;

namespace Moka.Simulator.Controllers;

public class PaymentQueriesController : Controller
{
 private readonly IPaymentQueryService _service;
 public PaymentQueriesController(IPaymentQueryService service) => _service = service;

 [HttpGet]
 public async Task<IActionResult> Index()
 {
 var list = await _service.GetPaymentsAsync();
 return View(list);
 }

 [HttpGet]
 public async Task<IActionResult> DetailByOther(string id)
 {
 var d = await _service.GetByOtherAsync(id);
 if (d == null) return NotFound();
 return View("Details", d);
 }

 [HttpGet]
 public async Task<IActionResult> DetailByTrx(string id)
 {
 var d = await _service.GetByTrxAsync(id);
 if (d == null) return NotFound();
 return View("Details", d);
 }
}
