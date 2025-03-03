using Android.Content;
using Android.Nfc;
using Android.Nfc.Tech;
using System;
using System.Security.Cryptography;
using VerifyIdentityProject.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using VerifyIdentityProject.Resources.Interfaces;
using Android.App;
using Xamarin.Google.Crypto.Tink.Subtle;
using Microsoft.Maui.Controls;
using Xamarin.Google.Crypto.Tink.Shaded.Protobuf;
using System.Runtime.Intrinsics.X86;
using System.Reflection.PortableExecutable;
using System.Runtime.Intrinsics.Arm;
using Xamarin.Google.Crypto.Tink.Util;
using Xamarin.Google.Crypto.Tink.Prf;
using Java.Lang.Ref;
using Android.Media.TV;
using Android.Graphics;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.IO;
using static AndroidX.Concurrent.Futures.CallbackToFutureAdapter;
using static Android.Graphics.PathIterator;
using System.Drawing;
using SkiaSharp;
using System.IO;


#if ANDROID
using static Android.OS.Environment;
using static Android.Provider.MediaStore;
using static Android.App.Application;
#endif

namespace VerifyIdentityProject.Platforms.Android
{
    public class DG2Parser
    {
        public class FaceImageInfo
        {
            public byte[] ImageData { get; set; }
            public string ImageFormat { get; set; }
            public string SavedFilePath { get; set; }
        }

        private class ASN1Length
        {
            public int Length { get; set; }
            public int BytesUsed { get; set; }
        }

        public static FaceImageInfo ParseDG2PaceAllJpegs(byte[] dg2Bytes, string fileNameBase = "passport_photo")
        {
            try
            {
                Console.WriteLine($"Starting JPEG2000 extraction from DG2, total DG2 length: {dg2Bytes.Length}");
                byte[] imageBytes = null;

                Console.WriteLine($"Starting DG2 PACE parse, total data length: {dg2Bytes.Length}");

                // Find and validate DG2 data
                int offset = 0;
                while (offset < dg2Bytes.Length - 2)
                {
                    // Look for biometric information tag (7F61)
                    if (dg2Bytes[offset] == 0x7F && dg2Bytes[offset + 1] == 0x61)
                    {
                        Console.WriteLine($"Found 7F61 tag at offset: {offset}");
                        break;
                    }
                    offset++;
                }

                if (offset >= dg2Bytes.Length - 2)
                    throw new Exception("Could not find the beginning of biometric data");

                // Skip 7F61 tag
                offset += 2;

                // Read the length of biometric data
                var bioLength = DecodeASN1Length(dg2Bytes, offset);
                offset += bioLength.BytesUsed;

                Console.WriteLine($"Biometric data length: {bioLength.Length}");

                // Look for image information (5F2E)
                while (offset < dg2Bytes.Length - 2)
                {
                    if (dg2Bytes[offset] == 0x5F && dg2Bytes[offset + 1] == 0x2E)
                    {
                        Console.WriteLine($"Found image tag 5F2E at offset: {offset}");
                        break;
                    }
                    offset++;
                }

                if (offset >= dg2Bytes.Length - 2)
                    throw new Exception("Could not find image data");

                // Skip 5F2E tag
                offset += 2;

                // Read the length of image data
                var imageLength = DecodeASN1Length(dg2Bytes, offset);
                offset += imageLength.BytesUsed;

                Console.WriteLine($"Image data length: {imageLength.Length}");

                int jpegStart = -1;
                string detectedFormat = "None";

                for (int i = offset; i < dg2Bytes.Length - 7; i++)
                {
                    // Check for JPEG header (FF D8 FF E0)
                    if (i < dg2Bytes.Length - 3 &&
                        dg2Bytes[i] == 0xFF &&
                        dg2Bytes[i + 1] == 0xD8 &&
                        dg2Bytes[i + 2] == 0xFF &&
                        dg2Bytes[i + 3] == 0xE0)
                    {
                        jpegStart = i;
                        detectedFormat = "JPEG";
                        break;
                    }

                    // Check for JPEG2000 header (00 00 00 0C 6A 50 20 20)
                    if (dg2Bytes[i] == 0x00 &&
                        dg2Bytes[i + 1] == 0x00 &&
                        dg2Bytes[i + 2] == 0x00 &&
                        dg2Bytes[i + 3] == 0x0C &&
                        dg2Bytes[i + 4] == 0x6A &&
                        dg2Bytes[i + 5] == 0x50 &&
                        dg2Bytes[i + 6] == 0x20 &&
                        dg2Bytes[i + 7] == 0x20)
                    {
                        jpegStart = i;
                        detectedFormat = "JPEG2000";
                        break;
                    }

                    // Check for JPEG2000 Code Stream header (FF 4F FF 51)
                    if (i < dg2Bytes.Length - 3 &&
                        dg2Bytes[i] == 0xFF &&
                        dg2Bytes[i + 1] == 0x4F &&
                        dg2Bytes[i + 2] == 0xFF &&
                        dg2Bytes[i + 3] == 0x51)
                    {
                        jpegStart = i;
                        detectedFormat = "JPEG2000 Code Stream";
                        break;
                    }
                }

                if (jpegStart != -1)
                {
                    Console.WriteLine($"Detected Format: {detectedFormat}, Start Position: {jpegStart}");
                }
                else
                {
                    throw new Exception("Could not find any valid JPEG file type.");
                }

                // Find JPEG end
                int jpegEnd = -1;
                for (int i = jpegStart; i < dg2Bytes.Length - 1; i++)
                {
                    if (dg2Bytes[i] == 0xFF && dg2Bytes[i + 1] == 0xD9)
                    {
                        jpegEnd = i + 2; // Include FF D9
                        Console.WriteLine($"JPEG end found at:{jpegEnd}");
                        break;
                    }
                }

                if (jpegEnd == -1)
                    throw new Exception("Could not find JPEG end marker (FF D9)");

                // Calculate actual JPEG size and copy the data
                int jpegLength = jpegEnd - jpegStart;
                byte[] jpegData = new byte[jpegLength];
                Array.Copy(dg2Bytes, jpegStart, jpegData, 0, jpegLength);

                // Extract image data
                Console.WriteLine($"Raw image data length before copying raw data over to jpegData: {dg2Bytes.Length}");
                Console.WriteLine($"First 16 bytes before copying raw data over to jpegData: {BitConverter.ToString(dg2Bytes.Take(16).ToArray())}");
                Console.WriteLine($"Last 20 bytes before copying raw data over to jpegData: {BitConverter.ToString(dg2Bytes.Skip(dg2Bytes.Length - 20).Take(20).ToArray())}");

                Console.WriteLine($"Data length after copying raw data over to jpegData: {jpegData.Length}");
                Console.WriteLine($"First 16 bytes after copying raw data over to jpegData: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
                Console.WriteLine($"Last 20 bytes after copying raw data over to jpegData: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 20).Take(20).ToArray())}");

                const int chunkSize = 100;
                for (int i = 0; i < jpegData.Length; i += chunkSize)
                {
                    int length = Math.Min(chunkSize, jpegData.Length - i);
                    var chunk = new byte[length];
                    Array.Copy(jpegData, i, chunk, 0, length);
                    //Console.WriteLine($"Chunk {i / chunkSize}: {BitConverter.ToString(chunk)}");
                }

                var pureImgData = RemovePaddingPace(jpegData);

                Console.WriteLine($"Final JPEG length after padding removal: {pureImgData.Length}");
                Console.WriteLine($"Final JPEG header: {BitConverter.ToString(pureImgData.Take(16).ToArray())}");
                Console.WriteLine($"Final JPEG footer: {BitConverter.ToString(pureImgData.Skip(pureImgData.Length - 16).Take(16).ToArray())}");

                if (jpegData.Length < 100)
                    throw new Exception($"Suspiciously short image data: {pureImgData.Length} bytes");

                FaceImageInfo faceInfo2 = new FaceImageInfo
                {
                    ImageData = pureImgData,
                    ImageFormat = "JP2"
                };

                string extension = "blabla";
                faceInfo2.SavedFilePath = AutoSaveImage(faceInfo2, fileNameBase, extension);
                Console.WriteLine($"Image saved path: {faceInfo2.SavedFilePath}");
                return faceInfo2;

            }
            catch (Exception ex)
            {
                throw new Exception("Error while parsing DG2 data: " + ex.Message, ex);
            }
        }

        public static byte[] ConvertJp2ToJpeg(byte[] jp2Data)
        {
            using var input = new MemoryStream(jp2Data);
            using var codec = SKCodec.Create(input);
            if (codec == null)
                throw new Exception("SKCodec creation failed.");

            using var bitmap = SKBitmap.Decode(codec);
            if (bitmap == null)
                throw new Exception("Decoding the image data failed.");

            using var output = new MemoryStream();
            bool encoded = bitmap.Encode(output, SKEncodedImageFormat.Jpeg, 100);
            if (!encoded)
                throw new Exception("Failed to encode the bitmap to JPEG format.");

            return output.ToArray();
        }

        private static string AutoSaveImage(FaceImageInfo faceInfo, string fileNameBase, string extension)
        {
            try
            {
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string fullFileName = $"{fileNameBase}_{timestamp}{extension}";

                // Decide MIME type based on extension
                string mimeType = "image/jpeg"; // fallback
                if (extension.Equals(".jp2", StringComparison.OrdinalIgnoreCase))
                {
                    mimeType = "image/jp2";
                }
                else if (extension.Equals(".j2k", StringComparison.OrdinalIgnoreCase))
                {
                    mimeType = "image/jp2";
                    // Some apps expect 'image/jp2' for J2K codestream, but it's not always recognized.
                    // Another possibility is "image/jpx" or "image/x-j2k" depending on the decoder.
                }

                var context = global::Android.App.Application.Context;
                var resolver = context.ContentResolver;
                ContentValues values = new ContentValues();
                values.Put(IMediaColumns.DisplayName, fullFileName);
                values.Put(IMediaColumns.MimeType, mimeType);
                values.Put(IMediaColumns.RelativePath, DirectoryPictures);

                var imageUri = resolver.Insert(Images.Media.ExternalContentUri, values);
                if (imageUri == null)
                    throw new Exception("Failed to create URI for saving the image.");

                using (var outputStream = resolver.OpenOutputStream(imageUri))
                {
                    if (outputStream == null)
                        throw new Exception("Failed to open output stream for saving the image.");

                    outputStream.Write(faceInfo.ImageData, 0, faceInfo.ImageData.Length);
                }

                Console.WriteLine($"Image saved: {imageUri.Path}");
                return imageUri.Path ?? "Unknown path";
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to save image: " + ex.Message, ex);
            }
        }

        

        //private static string AutoSaveImage(FaceImageInfo faceInfo, string fileName)
        //{
        //    try
        //    {
        //        // Bygg filnamn
        //        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        //        string fullFileName = $"{fileName}_{timestamp}.jpg";

        //        // Använd MediaStore för att spara bilden
        //        var context = global::Android.App.Application.Context;
        //        var resolver = context.ContentResolver;

        //        ContentValues values = new ContentValues();
        //        values.Put(IMediaColumns.DisplayName, fullFileName);
        //        values.Put(IMediaColumns.MimeType, "image/jpeg");
        //        values.Put(IMediaColumns.RelativePath, DirectoryPictures);

        //        var imageUri = resolver.Insert(Images.Media.ExternalContentUri, values);

        //        if (imageUri == null)
        //            throw new Exception("Kunde inte skapa URI för att spara bilden.");

        //        using (var outputStream = resolver.OpenOutputStream(imageUri))
        //        {
        //            if (outputStream == null)
        //            {
        //                throw new Exception("Kunde inte öppna OutputStream för att spara bilden.");
        //            }

        //            outputStream.Write(faceInfo.ImageData, 0, faceInfo.ImageData.Length);
        //        }

        //        Console.WriteLine($"Bilden sparades: {imageUri.Path}");
        //        return imageUri.Path ?? "Okänd sökväg";
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new Exception("Kunde inte spara bilden: " + ex.Message, ex);
        //    }
        //}
        
        private static ASN1Length DecodeASN1Length(byte[] data, int offset)
        {
            if (offset >= data.Length)
            {
                throw new Exception("Ogiltig offset för ASN.1 längd-avkodning");
            }

            if ((data[offset] & 0x80) == 0)
            {
                // Kort form
                return new ASN1Length { Length = data[offset], BytesUsed = 1 };
            }

            // Lång form
            int numLengthBytes = data[offset] & 0x7F;
            if (numLengthBytes > 4)
            {
                throw new Exception("För lång ASN.1 längd");
            }

            int length = 0;
            for (int i = 0; i < numLengthBytes; i++)
            {
                length = (length << 8) | data[offset + 1 + i];
            }

            return new ASN1Length { Length = length, BytesUsed = 1 + numLengthBytes };
        }

        // Revised RemovePaddingPace using a helper to detect an exact 16-byte padding block.
        private static bool IsPaddingBlock(byte[] input, int index)
        {
            if (index > input.Length - 16)
                return false;
            if (input[index] != 0x80)
                return false;
            for (int j = 1; j < 16; j++)
            {
                if (input[index + j] != 0x00)
                    return false;
            }
            return true;
        }

        public static byte[] RemovePaddingPace(byte[] input)
        {
            List<byte> result = new List<byte>();

            for (int i = 0; i < input.Length; i++)
            {
                // Check if we have found the start of a padding sequence (16 bytes: 80 00 ... 00)
                if (i <= input.Length - 16 &&
                    input[i] == 0x80 &&
                    input[i + 1] == 0x00 &&
                    input[i + 2] == 0x00 &&
                    input[i + 3] == 0x00 &&
                    input[i + 4] == 0x00 &&
                    input[i + 5] == 0x00 &&
                    input[i + 6] == 0x00 &&
                    input[i + 7] == 0x00 &&
                    input[i + 8] == 0x00 &&
                    input[i + 9] == 0x00 &&
                    input[i + 10] == 0x00 &&
                    input[i + 11] == 0x00 &&
                    input[i + 12] == 0x00 &&
                    input[i + 13] == 0x00 &&
                    input[i + 14] == 0x00 &&
                    input[i + 15] == 0x00)
                {
                    // Skip the padding sequence (advance index by 15, since the loop will add 1)
                    i += 15;
                    continue;
                }

                // Add the byte if it is not part of a padding sequence
                result.Add(input[i]);
            }

            return result.ToArray();
        }

        //public static byte[] RemovePaddingPace(byte[] input)
        //{
        //    List<byte> result = new List<byte>();

        //    for (int i = 0; i < input.Length; i++)
        //    {
        //        if (IsPaddingBlock(input, i))
        //        {
        //            // Skip exactly 16 bytes (current byte + next 15)
        //            i += 15;
        //            continue;
        //        }
        //        result.Add(input[i]);
        //    }

        //    return result.ToArray();
        //}


        private static byte[] PickOutJPGDataOnly(byte[] data)
        {
            int startIndex = -1;
            int endIndex = -1;
            Console.WriteLine($"Length of data:{data.Length}");

            // Hitta JPEG header (FF D8)
            for (int i = 0; i < data.Length - 1; i++)
            {
                if (data[i] == 0xFF && data[i + 1] == 0xD8)
                {
                    startIndex = i;
                    Console.WriteLine($"JPEG start index:{startIndex}");
                    break;
                }
            }

            // Hitta JPEG footer (FF D9)
            for (int i = data.Length - 2; i >= 0; i--)
            {
                if (data[i] == 0xFF && data[i + 1] == 0xD9)
                {
                    endIndex = i + 2; // Inkludera FF D9
                    Console.WriteLine($"JPEG end Index:{endIndex}");
                    break;
                }
            }

            if (startIndex == -1 || endIndex == -1)
                throw new Exception("Kunde inte hitta giltig JPEG-data");

            // Extrahera bara den faktiska JPEG-datan
            int length = endIndex - startIndex;
            byte[] jpegData = new byte[length];
            Array.Copy(data, startIndex, jpegData, 0, length);

            return jpegData;
        }

        private static bool IsValidJPEG(byte[] data)
        {
            if (data == null || data.Length < 4)
                return false;

            // Kontrollera JPEG signatur och slutmarkör
            if (data[0] != 0xFF || data[1] != 0xD8)
                return false;

            // Sök efter JPEG slutmarkör
            for (int i = data.Length - 2; i >= 0; i--)
            {
                if (data[i] == 0xFF && data[i + 1] == 0xD9)
                    return true;
            }

            return false;
        }

    }
}
