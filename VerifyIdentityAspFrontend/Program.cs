using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using VerifyIdentityAspFrontend.Data;
using VerifyIdentityAspFrontend.DTOs;
using VerifyIdentityAspFrontend.Models;
using VerifyIdentityAspFrontend.Services;
using VerifyIdentityAspFrontend.Services.IServices;

namespace VerifyIdentityAspFrontend
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString));
            builder.Services.AddDatabaseDeveloperPageExceptionFilter();

            builder.Services.AddDefaultIdentity<ApplicationUser>(options =>
            {
                options.SignIn.RequireConfirmedAccount = false;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>();

            builder.Services.AddScoped<IVerifyUserService, VerifyUserService>();

            builder.Services.AddDistributedMemoryCache();
            ////Adding Session for cookie--------------
            //builder.Services.AddSession(opt =>
            //{
            //    opt.Cookie.Name = ".AspNetCore.Session";
            //    opt.Cookie.HttpOnly = false; // Needed for Postman or JS to read it
            //    opt.Cookie.SameSite = SameSiteMode.Lax; // or None for cross-domain
            //    opt.Cookie.SecurePolicy = CookieSecurePolicy.None; // set to Always if using HTTPS
            //    opt.IdleTimeout = TimeSpan.FromMinutes(20);
            //    opt.Cookie.IsEssential = true;
            //});

            builder.Services.AddSession(opt =>
            {
                opt.Cookie.Name = ".AspNetCore.Session";
                opt.Cookie.HttpOnly = true;
                opt.Cookie.SameSite = SameSiteMode.Lax;
                opt.IdleTimeout = TimeSpan.FromMinutes(20);
                opt.Cookie.IsEssential = true;

                //// allow clear‐text during dev, require HTTPS in prod
                //opt.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                //    ? CookieSecurePolicy.None
                //    : CookieSecurePolicy.Always;

                opt.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            });


            //-----to use httpcontext as DI
            builder.Services.AddHttpContextAccessor();
            builder.Services.AddRazorPages();
            builder.Services.AddCors();
            builder.Services.AddScoped<VerifyUserService>();

            //-------------------------------------------------------------------------------------
            //-------------------------------------------------------------------------------------
            //-------------------------------------------------------------------------------------

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            // static files, HTTPS redirect
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            // ─── ROUTING & MIDDLEWARE ────────────────────────────────────────────────────
            // 1) Routing must come first
            app.UseRouting();

            // 2) Now the session middleware
            app.UseSession();

            // 3) Any CORS/auth/etc that relies on session or routing
            app.UseCors(policy => policy
                .AllowAnyOrigin()
                .AllowAnyHeader()
                .AllowAnyMethod());

            app.UseAuthentication();
            app.UseAuthorization();

            // ─── ENDPOINT MAPPING ────────────────────────────────────────────────────────
            app.MapPost("/userverification", async (IVerifyUserService verifyUserService, UserDTO userDTO) =>
            {
                try
                {
                    await verifyUserService.CheckUserDataAsync(userDTO);
                    return Results.Ok("User verified sueccesfully");
                }
                catch (Exception ex)
                {
                    return Results.BadRequest($"User verification faild: {ex.Message}");
                }

            });

            app.MapPost("/api/verify", async (
                [FromBody] PassportDataDto dto,
                IVerifyUserService verifyUserService
            ) =>
            {
                var status = await verifyUserService.ProcessVerificationAsync(
                    dto.OperationId,
                    dto.FirstName,
                    dto.LastName,
                    dto.SSN
                );

                // Return 200 for success, 409 for mismatch, 400 for other failures
                return status switch
                {
                    Status.Success => Results.Ok(new { status = "Success" }),
                    Status.Denied => Results.Conflict(new { status = "Denied" }),
                    _ => Results.BadRequest(new { status = "Error" })
                };
            });

            app.MapGet("/api/verify-status/{sessionId}", async (
                string sessionId,
                ApplicationDbContext db
            ) =>
            {
                if (string.IsNullOrWhiteSpace(sessionId))
                    return Results.BadRequest("Missing session ID.");

                var operation = await db.VerifyOperations
                    .OrderByDescending(v => v.QrCreated)
                    .FirstOrDefaultAsync(v => v.SessiondId == sessionId);

                if (operation == null)
                    return Results.NotFound();

                return Results.Ok(new
                {
                    status = operation.Status.ToString()
                });
            });

            app.MapGet("/test", () => { return "API Online"; });

            app.MapRazorPages();

            app.Run();
        }
    }
}
