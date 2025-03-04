using System;
using System.IO;
using FreeImageAPI;

namespace VerifyIdentityProject.Helpers
{
    public static class JP2Converter
    {
        public static byte[] ConvertJP2ToJpeg(byte[] jp2Data)
        {
            if (jp2Data == null || jp2Data.Length == 0)
                return null;

            try
            {
                // Spara JP2-data till en temporär fil
                string tempJp2Path = Path.Combine(FileSystem.CacheDirectory, "temp.jp2");
                string tempJpgPath = Path.Combine(FileSystem.CacheDirectory, "temp.jpg");

                File.WriteAllBytes(tempJp2Path, jp2Data);

                // Ladda JP2-filen med FreeImage
                var jp2Format = FREE_IMAGE_FORMAT.FIF_JP2;
                var dib = FreeImage.LoadEx(tempJp2Path, ref jp2Format);

                if (dib.IsNull)
                {
                    Console.WriteLine("Kunde inte ladda JP2-bilden");
                    return null;
                }

                // Sätt högre upplösning för bättre kvalitet
                FreeImage.SetResolutionX(dib, 300);
                FreeImage.SetResolutionY(dib, 300);

                // Spara med hög kvalitet
                bool result = FreeImage.Save(FREE_IMAGE_FORMAT.FIF_JPEG, dib, tempJpgPath,
                                            FREE_IMAGE_SAVE_FLAGS.JPEG_QUALITYSUPERB);

                // VIKTIGT: Frigör minnet explicit (GC gör inte detta)
                FreeImage.UnloadEx(ref dib);

                if (result && File.Exists(tempJpgPath))
                {
                    // Läs in den konverterade JPG-filen
                    byte[] jpegData = File.ReadAllBytes(tempJpgPath);

                    // Ta bort temporära filer
                    try
                    {
                        File.Delete(tempJp2Path);
                        File.Delete(tempJpgPath);
                    }
                    catch { }

                    return jpegData;
                }

                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid konvertering av JP2 till JPEG: {ex.Message}");
                return null;
            }
        }
    }
}