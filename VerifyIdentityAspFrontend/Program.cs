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

            //Adding Session for cookie--------------
            builder.Services.AddSession(opt =>
            {
                opt.Cookie.Name = ".AspNetCore.Session";
                opt.Cookie.HttpOnly = false; // Needed for Postman or JS to read it
                opt.Cookie.SameSite = SameSiteMode.Lax; // or None for cross-domain
                opt.Cookie.SecurePolicy = CookieSecurePolicy.None; // set to Always if using HTTPS
                opt.IdleTimeout = TimeSpan.FromMinutes(20);
                opt.Cookie.IsEssential = true;
            });

            //-----to use httpcontext as DI
            builder.Services.AddHttpContextAccessor();

            builder.Services.AddRazorPages();

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

            //endpoint for recieving data from mobile app
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

            //app.MapPost("/api/verify", async (
            //    [FromBody] VerifyRequestDto dto,
            //    ApplicationDbContext db,
            //    IHttpContextAccessor httpContextAccessor
            //) =>
            //{
            //    if (!VerificationStore.Verifications.TryGetValue(dto.Token, out var pending) || pending.QrExpired < DateTime.UtcNow)

            //        return Results.BadRequest("Invalid or expired verification token.");

            //    var user = await db.Users.Include(u => u.Person).FirstOrDefaultAsync(u => u.Id == pending.UserId);
            //    if (user == null)
            //        return Results.NotFound("User not found.");

            //    //  If user is already linked to a Person
            //    if (user.Person != null)
            //    {
            //        if (user.Person.SSN != dto.SSN)
            //        {
            //            return Results.Conflict("User is already linked to a different SSN.");
            //        }

            //        httpContextAccessor.HttpContext?.Session.SetString("UserVerified", "true");
            //        return Results.Ok("User already verified.");
            //    }

            //    //  Check if there's an existing Person with this SSN
            //    var existingPerson = await db.People.FirstOrDefaultAsync(p => p.SSN == dto.SSN);
            //    if (existingPerson != null)
            //    {
            //        existingPerson.UserId = user.Id;
            //        await db.SaveChangesAsync();

            //        httpContextAccessor.HttpContext?.Session.SetString("UserVerified", "true");
            //        return Results.Ok("Existing person linked to user.");
            //    }

            //    //  Create a new person and link it
            //    var newPerson = new Person
            //    {
            //        FirstName = dto.FirstName,
            //        LastName = dto.LastName,
            //        SSN = dto.SSN,
            //        UserId = user.Id
            //    };

            //    db.People.Add(newPerson);
            //    await db.SaveChangesAsync();

            //    httpContextAccessor.HttpContext?.Session.SetString("UserVerified", "true");
            //    return Results.Ok("New person created and linked to user.");
            //});

            app.MapPost("/api/verify", async (
                    [FromBody] VerifyRequestDto dto,
                    ApplicationDbContext db,
                    IHttpContextAccessor httpContextAccessor
                ) =>
            {
                // 1. Find the VerifyOperation
                if (!Guid.TryParse(dto.Token, out var operationId))
                    return Results.BadRequest("Invalid token format.");

                var verifyOp = await db.VerifyOperations.FindAsync(operationId);
                if (verifyOp == null || verifyOp.QrExpired < DateTime.UtcNow)
                    return Results.BadRequest("Invalid or expired verification token.");

                // 2. Find the user linked to this operation
                var user = await db.Users.Include(u => u.Person).FirstOrDefaultAsync(u => u.Id == verifyOp.UserId);
                if (user == null)
                    return Results.NotFound("User not found.");

                var session = httpContextAccessor.HttpContext?.Session;
                if (session == null)
                    return Results.BadRequest("Session not found.");

                // 3. If user has no Person => Create
                if (user.Person == null)
                {
                    var newPerson = new Person
                    {
                        FirstName = dto.FirstName,
                        LastName = dto.LastName,
                        SSN = dto.SSN,
                        UserId = user.Id
                    };

                    db.People.Add(newPerson);
                    await db.SaveChangesAsync();

                    session.SetString("UserVerified", "true");
                    session.SetString("VerificationStatus", "success");
                    return Results.Ok("New person created and linked to user.");
                }

                // 4. If person exists, validate values
                if (user.Person.FirstName == dto.FirstName &&
                    user.Person.LastName == dto.LastName &&
                    user.Person.SSN == dto.SSN)
                {
                    session.SetString("UserVerified", "true");
                    session.SetString("VerificationStatus", "success");
                    return Results.Ok("User verified.");
                }

                // ? Mismatch
                session.SetString("UserVerified", "false");
                session.SetString("VerificationStatus", "fail");
                return Results.Conflict("Passport data does not match user’s registered information.");
            });



            app.MapGet("/test", () => { return "hej"; });

            //activating session using


            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseSession();

            app.UseAuthorization();

            app.MapRazorPages();

            app.Run();
        }
    }
}
