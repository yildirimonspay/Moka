using Moka.Simulator.Models;
using System.Collections.Concurrent;

namespace Moka.Simulator.Services;

public class OrderService : IOrderService
{
    private static int _id = 1;
    private static readonly ConcurrentDictionary<string, Order> _ordersByTrx = new();
    private static readonly ConcurrentDictionary<int, Order> _ordersById = new();

    public Order Create(string trx, string trxCode, decimal amount, string currency, string maskedCard)
    {
        var order = new Order
        {
            Id = Interlocked.Increment(ref _id),
            Trx = trx,
            TrxCode = trxCode,
            Amount = amount,
            Currency = currency,
            MaskedCard = maskedCard,
            CreatedUtc = DateTime.UtcNow,
            Status = "Paid"
        };
        _ordersByTrx[trx] = order;
        _ordersById[order.Id] = order;
        return order;
    }

    public Order? GetByTrx(string trx) => _ordersByTrx.TryGetValue(trx, out var o) ? o : null;
    public Order? GetById(int id) => _ordersById.TryGetValue(id, out var o) ? o : null;
    public IReadOnlyCollection<Order> GetAll() => _ordersById.Values.OrderByDescending(o => o.CreatedUtc).ToList();
}
