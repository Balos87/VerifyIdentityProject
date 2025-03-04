using System;
using System.IO;
using FreeImageAPI;

namespace VerifyIdentityProject
{
    public static class ImageHelper
    {
        public static byte[] ConvertJpeg2000ToJpeg(byte[] imageData)
        {
            if (imageData == null || imageData.Length == 0)
            {
                Console.WriteLine("Ingen bilddata tillgänglig");
                return null;
            }

            try
            {
                // Skapa en MemoryStream från byte array
                using (MemoryStream inputStream = new MemoryStream(imageData))
                {
                    // Ladda bilden med FreeImage från strömmen
                    FIBITMAP dib = FreeImage.LoadFromStream(inputStream);

                    if (dib.IsNull)
                    {
                        Console.WriteLine("Kunde inte ladda bilden från JPEG2000-data");
                        return null;
                    }

                    // Skapa en ny MemoryStream för utdata
                    using (MemoryStream outputStream = new MemoryStream())
                    {
                        // Spara som JPEG till outputStream
                        bool result = FreeImage.SaveToStream(dib, outputStream, FREE_IMAGE_FORMAT.FIF_JPEG, FREE_IMAGE_SAVE_FLAGS.JPEG_QUALITYNORMAL);

                        // Viktigt: Frigör FreeImage-resurser för att undvika minnesläckor
                        FreeImage.Unload(dib);

                        if (result)
                        {
                            // Återställ strömmen till början och konvertera till byte array
                            outputStream.Position = 0;
                            byte[] convertedData = outputStream.ToArray();
                            Console.WriteLine($"Bild konverterad, storlek: {convertedData.Length} bytes");
                            return convertedData;
                        }
                    }
                }

                Console.WriteLine("Bildkonvertering misslyckades");
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid bildkonvertering: {ex.Message}");
                return null;
            }
        }
    }
}