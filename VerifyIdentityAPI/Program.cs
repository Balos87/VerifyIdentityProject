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
            app.MapPost("/api/convert/bytetojpg", async (HttpContext context) =>
            {
                try
                {
                    Console.WriteLine("Received image conversion request...");

                    // Log request headers
                    foreach (var header in context.Request.Headers)
                    {
                        Console.WriteLine($"Header: {header.Key} = {header.Value}");
                    }

                    // Ensure Content-Type is application/octet-stream
                    if (!context.Request.ContentType?.Contains("application/octet-stream") ?? true)
                    {
                        Console.WriteLine("Error: Missing or incorrect Content-Type. Expected 'application/octet-stream'.");
                        return Results.BadRequest("Unsupported Media Type - Content-Type must be 'application/octet-stream'.");
                    }

                    // Read request body as byte array
                    using var memoryStream = new MemoryStream();
                    await context.Request.Body.CopyToAsync(memoryStream);
                    byte[] inputBytes = memoryStream.ToArray();

                    Console.WriteLine($"Received byte array length: {inputBytes.Length}");

                    if (inputBytes.Length == 0)
                    {
                        Console.WriteLine("Error: No data received.");
                        return Results.BadRequest("No file uploaded.");
                    }

                    // Convert byte[] to JPG using Magick.NET
                    using var image = new MagickImage(inputBytes);
                    image.Format = MagickFormat.Jpeg;
                    byte[] jpgBytes = image.ToByteArray();

                    Console.WriteLine($"Conversion successful, output size: {jpgBytes.Length} bytes");

                    // Return raw byte array instead of a file
                    return Results.Bytes(jpgBytes, "image/jpeg");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Image conversion error: {ex.Message}");
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
