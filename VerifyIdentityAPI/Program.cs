using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Tesseract;
using VerifyIdentityAPI.Services;
using System.IO;
using Microsoft.AspNetCore.Mvc;
using System.Web.Mvc;
using ImageMagick;

namespace VerifyIdentityAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddAuthorization();

            // Register the Tesseract engine
            builder.Services.AddSingleton<TesseractEngine>(sp =>
            {
                return new TesseractEngine(@"./tessdata", "eng+ocrb+mrz+osd", EngineMode.Default);
            });

            builder.Services.AddSingleton<IMrzService, MrzService>();

            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(policy =>
                {
                    policy.AllowAnyOrigin() // Use this only for development testing
                          .AllowAnyHeader()
                          .AllowAnyMethod();
                });
            });

            var app = builder.Build();

            app.UseRouting(); // Ensure routing is configured first

            app.UseAuthorization();

            // Byte[] to JPG conversion endpoint
            app.MapPost("/api/convert/bytetojpg", async (byte[] inputBytes) =>
            {
                try
                {
                    if (inputBytes.Length == 0)
                        return Results.BadRequest("No file uploaded.");

                    // Convert byte to JPG
                    using var image = new MagickImage(inputBytes);
                    image.Format = MagickFormat.Jpeg;
                    byte[] jpgBytes = image.ToByteArray();

                    return Results.File(jpgBytes, "image/jpeg", "converted.jpg");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    return Results.StatusCode(500);
                }
            }).DisableAntiforgery();

            // Configure the health check endpoint
            app.MapGet("/api/health", () => Results.Ok("API is running"));

            // Configure the MRZ extraction endpoint
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

                    if(mrzText == string.Empty)
                    {
                        return Results.Ok(null);
                    }

                    return Results.Ok(mrzText);
                }

                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    return Results.StatusCode(500);
                }
            }).DisableAntiforgery(); // Allow anonymous access (bypassing anti-forgery)

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseCors(builder => builder
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader());

            app.Run();
        }
    }
}
