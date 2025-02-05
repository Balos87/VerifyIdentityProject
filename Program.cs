using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Tesseract;
using VerifyIdentityAPI.Services;
using System.IO;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Mvc;

namespace VerifyIdentityAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddAuthorization();

            builder.WebHost.ConfigureKestrel(options =>
            {
                options.ListenAnyIP(5000);  // Bind to all network interfaces on port 5000
            });

            // Register the Tesseract engine
            builder.Services.AddSingleton<TesseractEngine>(sp =>
            {
                // You can adjust the language as needed (e.g., "eng" for English)
                string tessDataPath = Path.Combine(Directory.GetCurrentDirectory(), "tessdata");
                return new TesseractEngine(tessDataPath, "eng", EngineMode.Default);
            });

            builder.Services.AddSingleton<IMrzService, MrzService>();

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseRouting(); // This should come before authorization

            app.UseAuthorization();

            // Define the MRZ extraction endpoint
            app.MapPost("/api/mrz/extract", async (IFormFile file, IMrzService mrzService) =>
            {
                if (file == null || file.Length == 0)
                    return Results.BadRequest("No file uploaded.");

                try
                {
                    // Save the uploaded file temporarily
                    var tempFilePath = Path.GetTempFileName();
                    await using (var stream = new FileStream(tempFilePath, FileMode.Create))
                    {
                        await file.CopyToAsync(stream);
                    }

                    // Use the MRZ service to process the file and extract MRZ
                    var mrzText = await mrzService.ExtractMrzAsync(tempFilePath);

                    // Delete the temporary file
                    File.Delete(tempFilePath);

                    return Results.Ok(mrzText);
                }
                catch (Exception ex)
                {
                    return Results.StatusCode(500);
                }
            }).WithName("ExtractMrz").WithMetadata(new IgnoreAntiforgeryTokenAttribute());

            app.Run();
        }
    }
}
