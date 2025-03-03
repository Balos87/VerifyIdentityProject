using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ImageMagick;
using System.IO;

namespace VerifyIdentityProject.Platforms.Android
{
    public static class ImageConversionHelper
    {
        /// <summary>
        /// Converts a JP2 image (provided as a byte array) to a JPEG image.
        /// </summary>
        /// <param name="jp2Data">The input JP2 image data.</param>
        /// <returns>A byte array containing the converted JPEG image.</returns>
        /// <exception cref="Exception">Thrown when conversion fails.</exception>
        public static byte[] ConvertJp2ToJpeg_Magick(byte[] jp2Data)
        {
            if (jp2Data == null || jp2Data.Length == 0)
            {
                Console.WriteLine("ERROR: JP2 data is null or empty.");
                throw new ArgumentException("JP2 data is null or empty.", nameof(jp2Data));
            }

            Console.WriteLine("Starting conversion from JP2 to JPEG using Magick.NET.");
            Console.WriteLine($"Input JP2 data length: {jp2Data.Length} bytes");

            try
            {
                Console.WriteLine("Attempting to create MagickImage instance from JP2 data.");
                using (var image = new MagickImage(jp2Data))
                {
                    Console.WriteLine("MagickImage instance created successfully.");
                    Console.WriteLine($"Detected input image format: {image.Format}");

                    Console.WriteLine("Setting output image format to JPEG.");
                    image.Format = MagickFormat.Jpeg;
                    Console.WriteLine($"Image format is now set to: {image.Format}");

                    // Optionally adjust image quality
                    // image.Quality = 90;
                    // Console.WriteLine("Image quality set to 90.");

                    Console.WriteLine("Encoding image to JPEG format.");
                    byte[] jpegData = image.ToByteArray();
                    Console.WriteLine($"Image encoded successfully. Output JPEG data length: {jpegData.Length} bytes");

                    return jpegData;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR during conversion: " + ex.Message);
                throw new Exception("Conversion from JP2 to JPEG failed: " + ex.Message, ex);
            }
        }
    }
}
