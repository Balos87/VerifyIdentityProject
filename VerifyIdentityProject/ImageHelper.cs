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
                }

                // Om det inte är JPEG2000 eller konverteringen misslyckades, returnera originaldata
                return imageData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid bildkonvertering: {ex.Message}");
                return imageData; // Returnera originaldata vid fel
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
    }
}