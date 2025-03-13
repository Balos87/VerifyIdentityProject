using System;
using System.IO;
using SkiaSharp;
using Microsoft.Maui.Controls;

namespace VerifyIdentityProject.Helpers
{
    public static class SkiaImageHelper
    {
        public static byte[] ProcessImage(byte[] imageData)
        {
            if (imageData == null || imageData.Length == 0)
            {
                Console.WriteLine("No image data available");
                return null;
            }

            try
            {
                // Use SkiaSharp to decode the image (supports JPEG2000)
                using (var inputStream = new SKMemoryStream(imageData))
                {
                    // Try decoding the image with SkiaSharp
                    using (var codec = SKCodec.Create(inputStream))
                    {
                        if (codec != null)
                        {
                            // Get image information
                            var info = codec.Info;
                            Console.WriteLine($"Decoded image: {info.Width}x{info.Height}");

                            // Create a bitmap to hold the image
                            using (var bitmap = new SKBitmap(info.Width, info.Height, info.ColorType, info.AlphaType))
                            {
                                // Decode the image into the bitmap
                                var result = codec.GetPixels(bitmap.Info, bitmap.GetPixels());
                                if (result == SKCodecResult.Success || result == SKCodecResult.IncompleteInput)
                                {
                                    // Convert to JPEG
                                    using (var image = SKImage.FromBitmap(bitmap))
                                    using (var data = image.Encode(SKEncodedImageFormat.Jpeg, 90))
                                    {
                                        // Convert to byte array
                                        return data.ToArray();
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"Could not decode the image, result: {result}");
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine("Could not create codec for the image");
                        }
                    }
                }

                // If decoding fails, create a placeholder image
                return CreatePlaceholderImage();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing image: {ex.Message}");
                return CreatePlaceholderImage();
            }
        }

        private static byte[] CreatePlaceholderImage()
        {
            try
            {
                // Create a simple placeholder image
                int width = 100;
                int height = 130;

                using (var surface = SKSurface.Create(new SKImageInfo(width, height)))
                {
                    var canvas = surface.Canvas;

                    // Background color
                    canvas.Clear(SKColors.LightGray);

                    // Border
                    using (var paint = new SKPaint
                    {
                        Color = SKColors.Gray,
                        IsStroke = true,
                        StrokeWidth = 2
                    })
                    {
                        canvas.DrawRect(1, 1, width - 2, height - 2, paint);
                    }

                    // Text
                    using (var paint = new SKPaint
                    {
                        Color = SKColors.Black,
                        TextSize = 14,
                        TextAlign = SKTextAlign.Center
                    })
                    {
                        canvas.DrawText("Passport Photo", width / 2, height / 2, paint);
                    }

                    // Export as PNG
                    using (var image = surface.Snapshot())
                    using (var data = image.Encode(SKEncodedImageFormat.Png, 100))
                    {
                        return data.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creating placeholder image: {ex.Message}");

                // Return a minimal PNG as a last resort
                return new byte[] {
                    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
                    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
                    0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
                    0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
                    0x44, 0xAE, 0x42, 0x60, 0x82
                };
            }
        }
    }
}
