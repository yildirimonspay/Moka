using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Moka.Api.Migrations
{
 public partial class _0001_Initial : Migration
 {
 protected override void Up(MigrationBuilder migrationBuilder)
 {
 migrationBuilder.CreateTable(
 name: "Payments",
 columns: table => new
 {
 Id = table.Column<int>(type: "INTEGER", nullable: false)
 .Annotation("Sqlite:Autoincrement", true),
 OtherTrxCode = table.Column<string>(type: "TEXT", nullable: false),
 TrxCode = table.Column<string>(type: "TEXT", nullable: false),
 CodeForHash = table.Column<string>(type: "TEXT", nullable: false),
 Amount = table.Column<decimal>(type: "TEXT", nullable: false),
 Currency = table.Column<string>(type: "TEXT", maxLength:8, nullable: false),
 Status = table.Column<string>(type: "TEXT", maxLength:32, nullable: false),
 CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
 },
 constraints: table =>
 {
 table.PrimaryKey("PK_Payments", x => x.Id);
 });

 migrationBuilder.CreateIndex(
 name: "IX_Payments_OtherTrxCode",
 table: "Payments",
 column: "OtherTrxCode",
 unique: true);

 migrationBuilder.CreateIndex(
 name: "IX_Payments_TrxCode",
 table: "Payments",
 column: "TrxCode",
 unique: true);
 }

 protected override void Down(MigrationBuilder migrationBuilder)
 {
 migrationBuilder.DropTable(
 name: "Payments");
 }
 }
}
