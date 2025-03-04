using System;
using System.IO;
using SkiaSharp;
using Microsoft.Maui.Controls;

namespace VerifyIdentityProject
{
    public static class SkiaImageHelper
    {
        public static byte[] ProcessImage(byte[] imageData)
        {
            if (imageData == null || imageData.Length == 0)
            {
                Console.WriteLine("Ingen bilddata tillgänglig");
                return null;
            }

            try
            {
                // Använd SkiaSharp för att dekoda bilden (stöder JPEG2000)
                using (var inputStream = new SKMemoryStream(imageData))
                {
                    // Försök dekoda bilden med SkiaSharp
                    using (var codec = SKCodec.Create(inputStream))
                    {
                        if (codec != null)
                        {
                            // Få information om bilden
                            var info = codec.Info;
                            Console.WriteLine($"Dekodad bild: {info.Width}x{info.Height}");

                            // Skapa en bitmap för att hålla bilden
                            using (var bitmap = new SKBitmap(info.Width, info.Height, info.ColorType, info.AlphaType))
                            {
                                // Dekoda bilden till bitmap
                                var result = codec.GetPixels(bitmap.Info, bitmap.GetPixels());
                                if (result == SKCodecResult.Success || result == SKCodecResult.IncompleteInput)
                                {
                                    // Konvertera till JPEG
                                    using (var image = SKImage.FromBitmap(bitmap))
                                    using (var data = image.Encode(SKEncodedImageFormat.Jpeg, 90))
                                    {
                                        // Konvertera till byte-array
                                        return data.ToArray();
                                    }
                                }
                                else
                                {
                                    Console.WriteLine($"Kunde inte dekoda bilden, resultat: {result}");
                                }
                            }
                        }
                        else
                        {
                            Console.WriteLine("Kunde inte skapa codec för bilden");
                        }
                    }
                }

                // Om dekodningen misslyckades, skapa en platshållarbild
                return CreatePlaceholderImage();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid bildbehandling: {ex.Message}");
                return CreatePlaceholderImage();
            }
        }

        private static byte[] CreatePlaceholderImage()
        {
            try
            {
                // Skapa en enkel platshållarbild
                int width = 100;
                int height = 130;

                using (var surface = SKSurface.Create(new SKImageInfo(width, height)))
                {
                    var canvas = surface.Canvas;

                    // Bakgrundsfärg
                    canvas.Clear(SKColors.LightGray);

                    // Ram
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
                        canvas.DrawText("Passbild", width / 2, height / 2, paint);
                    }

                    // Exportera som PNG
                    using (var image = surface.Snapshot())
                    using (var data = image.Encode(SKEncodedImageFormat.Png, 100))
                    {
                        return data.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid skapande av platshållarbild: {ex.Message}");

                // Returnera en minimal PNG som sista utväg
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