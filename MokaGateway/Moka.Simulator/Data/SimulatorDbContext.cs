using Microsoft.EntityFrameworkCore;

namespace Moka.Simulator.Data;

public class SimulatorDbContext : DbContext
{
    public SimulatorDbContext(DbContextOptions<SimulatorDbContext> options) : base(options) { }
    public DbSet<HttpLog> HttpLogs => Set<HttpLog>();
    public DbSet<PaymentSession> PaymentSessions => Set<PaymentSession>();
    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<HttpLog>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Direction).HasMaxLength(16);
            e.Property(x => x.Url).HasMaxLength(512);
            e.Property(x => x.Method).HasMaxLength(16);
        });
        b.Entity<PaymentSession>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.OtherTrxCode).IsUnique();
            e.Property(x => x.Currency).HasMaxLength(8);
            e.Property(x => x.MaskedCard).HasMaxLength(32);
            e.Property(x => x.MerchantNonce).HasMaxLength(64);
        });
    }
}

public class HttpLog
{
    public long Id { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public string Direction { get; set; } = string.Empty; // Outbound/Inbound
    public string Url { get; set; } = string.Empty;
    public string Method { get; set; } = string.Empty;
    public string RequestHeaders { get; set; } = string.Empty;
    public string RequestBody { get; set; } = string.Empty;
    public int? StatusCode { get; set; }
    public string ResponseHeaders { get; set; } = string.Empty;
    public string ResponseBody { get; set; } = string.Empty;
}

public class PaymentSession
{
    public int Id { get; set; }
    public string OtherTrxCode { get; set; } = string.Empty;
    public string CodeForHash { get; set; } = string.Empty;
    public decimal Amount { get; set; }
    public string Currency { get; set; } = "TL";
    public string MaskedCard { get; set; } = string.Empty;
    public string? TrxCode { get; set; }
    public string? MerchantNonce { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}
