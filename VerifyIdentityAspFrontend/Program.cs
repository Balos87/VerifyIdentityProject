using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using VerifyIdentityAspFrontend.Data;
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

            builder.Services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApplicationDbContext>();


            builder.Services.AddScoped<IVerifyUserService, VerifyUserService>();

            //Adding Session for cookie--------------
            builder.Services.AddSession(opt =>
            {
                opt.IdleTimeout = TimeSpan.FromMinutes(20);
                opt.Cookie.IsEssential = true;
            });

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
                var result = await verifyUserService.CheckUserDataAsync(userDTO);

                return result ? Results.Ok("User verified sueccesfully") : Results.BadRequest("User verification faild");
            });

            //activating session using
            app.UseSession();

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.MapRazorPages();

            app.Run();
        }
    }
}
