using Moka.Simulator.Models;

namespace Moka.Simulator.Services;

public interface IOrderService
{
 Order Create(string trx, string trxCode, decimal amount, string currency, string maskedCard);
 Order? GetByTrx(string trx);
 Order? GetById(int id);
 IReadOnlyCollection<Order> GetAll();
}
