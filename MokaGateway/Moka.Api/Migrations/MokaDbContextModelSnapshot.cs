using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Moka.Api.Data;

#nullable disable

namespace Moka.Api.Migrations
{
 [DbContext(typeof(MokaDbContext))]
 partial class MokaDbContextModelSnapshot : ModelSnapshot
 {
 protected override void BuildModel(ModelBuilder modelBuilder)
 {
 modelBuilder.HasAnnotation("ProductVersion", "8.0.5");

 modelBuilder.Entity("Moka.Api.Data.PaymentEntity", b =>
 {
 b.Property<int>("Id").ValueGeneratedOnAdd().HasColumnType("INTEGER");
 b.Property<decimal>("Amount").HasColumnType("TEXT");
 b.Property<string>("CodeForHash").IsRequired().HasColumnType("TEXT");
 b.Property<string>("Currency").IsRequired().HasMaxLength(8).HasColumnType("TEXT");
 b.Property<DateTime>("CreatedUtc").HasColumnType("TEXT");
 b.Property<string>("OtherTrxCode").IsRequired().HasColumnType("TEXT");
 b.Property<string>("Status").IsRequired().HasMaxLength(32).HasColumnType("TEXT");
 b.Property<string>("TrxCode").IsRequired().HasColumnType("TEXT");
 b.HasKey("Id");
 b.HasIndex("OtherTrxCode").IsUnique();
 b.HasIndex("TrxCode").IsUnique();
 b.ToTable("Payments");
 });
 }
 }
}
