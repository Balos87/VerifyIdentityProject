using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VerifyIdentityAspFrontend.Data.Migrations
{
    /// <inheritdoc />
    public partial class UpdatedRelations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_People_SSN",
                table: "People");

            migrationBuilder.AlterColumn<string>(
                name: "UserId",
                table: "VerifyOperations",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.AlterColumn<string>(
                name: "SSN",
                table: "People",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.CreateIndex(
                name: "IX_VerifyOperations_UserId",
                table: "VerifyOperations",
                column: "UserId");

            migrationBuilder.AddForeignKey(
                name: "FK_VerifyOperations_AspNetUsers_UserId",
                table: "VerifyOperations",
                column: "UserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_VerifyOperations_AspNetUsers_UserId",
                table: "VerifyOperations");

            migrationBuilder.DropIndex(
                name: "IX_VerifyOperations_UserId",
                table: "VerifyOperations");

            migrationBuilder.AlterColumn<string>(
                name: "UserId",
                table: "VerifyOperations",
                type: "nvarchar(max)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)");

            migrationBuilder.AlterColumn<string>(
                name: "SSN",
                table: "People",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(max)");

            migrationBuilder.CreateIndex(
                name: "IX_People_SSN",
                table: "People",
                column: "SSN",
                unique: true);
        }
    }
}
