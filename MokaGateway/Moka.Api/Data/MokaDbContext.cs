using Microsoft.EntityFrameworkCore;

namespace Moka.Api.Data;

public class MokaDbContext : DbContext
{
    public MokaDbContext(DbContextOptions<MokaDbContext> options) : base(options) { }
    public DbSet<PaymentEntity> Payments => Set<PaymentEntity>();
    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<PaymentEntity>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.OtherTrxCode).IsUnique();
            e.HasIndex(x => x.TrxCode).IsUnique();
            e.Property(x => x.Currency).HasMaxLength(8);
            e.Property(x => x.Status).HasMaxLength(32);
        });
    }
}

public class PaymentEntity
{
    public int Id { get; set; }
    public string OtherTrxCode { get; set; } = string.Empty;
    public string TrxCode { get; set; } = string.Empty;
    public string CodeForHash { get; set; } = string.Empty;
    public decimal Amount { get; set; }
    public string Currency { get; set; } = "TL";
    public string Status { get; set; } = "Pending3D";
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}
