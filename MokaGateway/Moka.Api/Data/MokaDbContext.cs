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
            e.ToTable("Payments");
            e.HasKey(x => x.Id);

            // required and bounded lengths for indexed/text columns
            e.Property(x => x.OtherTrxCode).IsRequired().HasMaxLength(128);
            e.Property(x => x.TrxCode).IsRequired().HasMaxLength(64);
            e.Property(x => x.ThreeDTrxCode).IsRequired().HasMaxLength(64);
            e.Property(x => x.CodeForHash).IsRequired().HasMaxLength(128);
            e.Property(x => x.RedirectUrl).IsRequired().HasMaxLength(2048);
            e.Property(x => x.Nonce).IsRequired().HasMaxLength(64);
            e.Property(x => x.AuthorizationCode).HasMaxLength(32);
            e.Property(x => x.CardBin).HasMaxLength(8);
            e.Property(x => x.Currency).IsRequired().HasMaxLength(8);
            e.Property(x => x.Status).IsRequired().HasMaxLength(32);

            // numeric/date
            e.Property(x => x.Amount).HasColumnType("decimal(18,2)");
            e.Property(x => x.CreatedUtc).HasDefaultValueSql("SYSUTCDATETIME()");

            // indexes
            e.HasIndex(x => x.OtherTrxCode).IsUnique();
            e.HasIndex(x => x.TrxCode).IsUnique();
            e.HasIndex(x => x.ThreeDTrxCode).IsUnique();
            e.HasIndex(x => x.Nonce);
            e.HasIndex(x => x.CardBin);
        });
    }
}

public class PaymentEntity
{
    public int Id { get; set; }
    public string OtherTrxCode { get; set; } = string.Empty;
    public string TrxCode { get; set; } = string.Empty;
    public string CodeForHash { get; set; } = string.Empty;
    public string ThreeDTrxCode { get; set; } = string.Empty;
    public string RedirectUrl { get; set; } = string.Empty;
    public string Nonce { get; set; } = string.Empty;
    public string AuthorizationCode { get; set; } = string.Empty; // generated on authorization success
    public string CardBin { get; set; } = string.Empty; // first6 digits of card
    public int OtpFailCount { get; set; } =0;
    public int OtpMaxAttempts { get; set; } =3;
    public DateTime? OtpExpiresUtc { get; set; } = null;
    public decimal Amount { get; set; }
    public string Currency { get; set; } = "TL";
    public string Status { get; set; } = "Pending3D";
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}
