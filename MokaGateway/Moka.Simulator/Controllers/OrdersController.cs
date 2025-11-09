using Microsoft.AspNetCore.Mvc;
using Moka.Simulator.Services;

namespace Moka.Simulator.Controllers;

public class OrdersController : Controller
{
 private readonly IOrderService _orders;

 public OrdersController(IOrderService orders)
 {
 _orders = orders;
 }

 [HttpGet]
 public IActionResult Index()
 {
 var list = _orders.GetAll();
 return View(list);
 }

 [HttpGet]
 public IActionResult Details(int id)
 {
 var order = _orders.GetById(id);
 if (order == null) return NotFound();
 return View(order);
 }
}
