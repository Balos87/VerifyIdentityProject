using SkiaSharp;
using System;
using System.IO;

namespace VerifyIdentityProject
{
    public static class ImageHelper
    {
        public static byte[] ConvertJpeg2000ToJpeg(byte[] imageData)
        {
            try
            {
                // Försök identifiera om det är JPEG2000 format
                if (IsJpeg2000(imageData))
                {
                    Console.WriteLine("JPEG2000 format identifierat, konverterar...");

                    // Använd SkiaSharp för att ladda och konvertera bilden
                    using (var inputStream = new MemoryStream(imageData))
                    {
                        // Ladda bilden med SkiaSharp
                        using (var bitmap = SKBitmap.Decode(inputStream))
                        {
                            if (bitmap != null)
                            {
                                // Konvertera till JPEG
                                using (var outputStream = new MemoryStream())
                                {
                                    using (var image = SKImage.FromBitmap(bitmap))
                                    {
                                        var data = image.Encode(SKEncodedImageFormat.Jpeg, 90);
                                        data.SaveTo(outputStream);
                                    }

                                    Console.WriteLine("Bilden har konverterats från JPEG2000 till JPEG");
                                    return outputStream.ToArray();
                                }
                            }
                        }
                    }

                    Console.WriteLine("Kunde inte konvertera bild");
                    // Om konverteringen misslyckades, prova fallback-metoden
                    return CreateFallbackImage(imageData);
                }

                // Om det inte är JPEG2000, returnera originaldata
                return imageData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid bildkonvertering: {ex.Message}");
                // Vid fel, försök med fallback-metoden
                return CreateFallbackImage(imageData);
            }
        }

        private static bool IsJpeg2000(byte[] data)
        {
            // JPEG2000-filer börjar ofta med signatur: 0x0000 000C 6A50 2020 0D0A
            if (data.Length < 12)
                return false;

            // Kontrollera om det matchar början av en JP2-signatur
            return (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x0C &&
                    data[4] == 0x6A && data[5] == 0x50 && data[6] == 0x20 && data[7] == 0x20) ||
                   // Alternativ signatur för vissa JPEG2000-filer
                   (data[0] == 0xFF && data[1] == 0x4F && data[2] == 0xFF);
        }

        private static byte[] CreateFallbackImage(byte[] originalData)
        {
            try
            {
                // Skapa en ny bitmap
                using (var bitmap = new SKBitmap(300, 400))
                {
                    // Fyll med en ljusgrå bakgrund
                    using (var canvas = new SKCanvas(bitmap))
                    {
                        canvas.Clear(SKColors.LightGray);

                        try
                        {
                            // Försök dekoda originalbilden
                            var originalBitmap = SKBitmap.Decode(originalData);
                            if (originalBitmap != null)
                            {
                                // Beräkna position för att centrera bilden
                                float scaleX = (float)bitmap.Width / originalBitmap.Width;
                                float scaleY = (float)bitmap.Height / originalBitmap.Height;
                                float scale = Math.Min(scaleX, scaleY);

                                int scaledWidth = (int)(originalBitmap.Width * scale);
                                int scaledHeight = (int)(originalBitmap.Height * scale);
                                int x = (bitmap.Width - scaledWidth) / 2;
                                int y = (bitmap.Height - scaledHeight) / 2;

                                // Rita den originala bilden på canvas
                                var destRect = new SKRect(x, y, x + scaledWidth, y + scaledHeight);
                                canvas.DrawBitmap(originalBitmap, destRect);
                            }
                            else
                            {
                                // Rita en text att bilden inte kunde laddas
                                var paint = new SKPaint
                                {
                                    Color = SKColors.Black,
                                    TextSize = 20,
                                    TextAlign = SKTextAlign.Center
                                };
                                canvas.DrawText("Bilden kunde inte visas", bitmap.Width / 2, bitmap.Height / 2, paint);
                            }
                        }
                        catch
                        {
                            // Minimal fallback om inget annat fungerar
                            var paint = new SKPaint
                            {
                                Color = SKColors.Black,
                                TextSize = 20,
                                TextAlign = SKTextAlign.Center
                            };
                            canvas.DrawText("Passbild", bitmap.Width / 2, bitmap.Height / 2, paint);
                        }
                    }

                    // Konvertera till JPEG
                    using (var image = SKImage.FromBitmap(bitmap))
                    {
                        var data = image.Encode(SKEncodedImageFormat.Jpeg, 90);
                        return data.ToArray();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid skapande av fallback-bild: {ex.Message}");
                return originalData;
            }
        }
    }
}