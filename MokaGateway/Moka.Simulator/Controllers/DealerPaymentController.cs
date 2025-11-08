using Microsoft.AspNetCore.Mvc;
using Moka.Simulator.Models;

namespace Moka.Simulator.Controllers;

public class DealerPaymentController : Controller
{
 [HttpGet]
 public IActionResult Create()
 {
 var model = BuildNewModel();
 return View(model);
 }

 [HttpPost]
 [ValidateAntiForgeryToken]
 public IActionResult Create(DealerPaymentInputModel model)
 {
 if (!ModelState.IsValid)
 {
 // repopulate dropdowns
 PopulateLists(model);
 return View(model);
 }

 // Map to request DTO (could later POST to Moka.Api)
 var request = new DealerPaymentServicePaymentRequest
 {
 PaymentDealerAuthentication = new PaymentDealerAuthentication
 {
 DealerCode = model.DealerCode,
 Username = model.Username,
 Password = model.Password,
 CheckKey = model.CheckKey
 },
 PaymentDealerRequest = new PaymentDealerRequest
 {
 CardHolderFullName = model.CardHolderFullName,
 CardNumber = model.CardNumber,
 ExpMonth = model.ExpMonth,
 ExpYear = model.ExpYear,
 CvcNumber = model.CvcNumber,
 Amount = model.Amount,
 Currency = model.Currency,
 InstallmentNumber = model.InstallmentNumber,
 VirtualPosOrderId = model.VirtualPosOrderId,
 OtherTrxCode = model.OtherTrxCode,
 VoidRefundReason = model.VoidRefundReason,
 ClientIP = model.ClientIP,
 RedirectUrl = model.RedirectUrl
 }
 };

 // For now just echo back (later call external API)
 TempData["LastPaymentJson"] = System.Text.Json.JsonSerializer.Serialize(request);
 return RedirectToAction("Success");
 }

 public IActionResult Success()
 {
 ViewBag.Json = TempData["LastPaymentJson"] as string;
 return View();
 }

 private DealerPaymentInputModel BuildNewModel()
 {
 var model = new DealerPaymentInputModel();
 PopulateLists(model);
 return model;
 }

 private void PopulateLists(DealerPaymentInputModel model)
 {
 model.ExpireMonths = Enumerable.Range(1,12)
 .Select(i => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Value = i.ToString("00"), Text = i.ToString("00") })
 .ToList();
 var year = DateTime.UtcNow.Year;
 model.ExpireYears = Enumerable.Range(0,15)
 .Select(i => new Microsoft.AspNetCore.Mvc.Rendering.SelectListItem { Value = (year + i).ToString(), Text = (year + i).ToString() })
 .ToList();
 }
}
