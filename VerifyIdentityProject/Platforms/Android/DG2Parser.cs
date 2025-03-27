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
using VerifyIdentityProject.Services;


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

        public static async Task<FaceImageInfo> ParseDG2PaceAllJpegs(byte[] dg2Bytes, string apiUrl, string fileNameBase = "passport_photo")
        {
            try
            {
                //  Console.WriteLine($"Starting JPEG2000 extraction from DG2, total DG2 length: {dg2Bytes.Length}");

                int offset = 0;
                while (offset < dg2Bytes.Length - 2)
                {
                    if (dg2Bytes[offset] == 0x7F && dg2Bytes[offset + 1] == 0x61)
                    {
                        //  Console.WriteLine($"Found 7F61 tag at offset: {offset}");
                        break;
                    }
                    offset++;
                }

                if (offset >= dg2Bytes.Length - 2)
                    throw new Exception("Could not find the beginning of biometric data");

                offset += 2;
                var bioLength = DecodeASN1Length(dg2Bytes, offset);
                offset += bioLength.BytesUsed;

                while (offset < dg2Bytes.Length - 2)
                {
                    if (dg2Bytes[offset] == 0x5F && dg2Bytes[offset + 1] == 0x2E)
                    {
                        //  Console.WriteLine($"Found image tag 5F2E at offset: {offset}");
                        break;
                    }
                    offset++;
                }

                if (offset >= dg2Bytes.Length - 2)
                    throw new Exception("Could not find image data");

                offset += 2;
                var imageLength = DecodeASN1Length(dg2Bytes, offset);
                offset += imageLength.BytesUsed;

                //  Console.WriteLine($"Image data length: {imageLength.Length}");

                int jpegStart = -1;
                string detectedFormat = "None";

                for (int i = offset; i < dg2Bytes.Length - 7; i++)
                {
                    if (i < dg2Bytes.Length - 3 &&
                        dg2Bytes[i] == 0xFF && dg2Bytes[i + 1] == 0xD8 &&
                        dg2Bytes[i + 2] == 0xFF && dg2Bytes[i + 3] == 0xE0)
                    {
                        jpegStart = i;
                        detectedFormat = "JPEG";
                        break;
                    }

                    if (dg2Bytes[i] == 0x00 && dg2Bytes[i + 1] == 0x00 &&
                        dg2Bytes[i + 2] == 0x00 && dg2Bytes[i + 3] == 0x0C &&
                        dg2Bytes[i + 4] == 0x6A && dg2Bytes[i + 5] == 0x50 &&
                        dg2Bytes[i + 6] == 0x20 && dg2Bytes[i + 7] == 0x20)
                    {
                        jpegStart = i;
                        detectedFormat = "JPEG2000";
                        break;
                    }

                    if (i < dg2Bytes.Length - 3 &&
                        dg2Bytes[i] == 0xFF && dg2Bytes[i + 1] == 0x4F &&
                        dg2Bytes[i + 2] == 0xFF && dg2Bytes[i + 3] == 0x51)
                    {
                        jpegStart = i;
                        detectedFormat = "JPEG2000 Code Stream";
                        break;
                    }
                }

                if (jpegStart == -1)
                    throw new Exception("Could not find any valid JPEG file type.");

                Console.WriteLine($"Detected Format: {detectedFormat}, Start Position: {jpegStart}");

                int jpegEnd = -1;
                for (int i = jpegStart; i < dg2Bytes.Length - 1; i++)
                {
                    if (dg2Bytes[i] == 0xFF && dg2Bytes[i + 1] == 0xD9)
                    {
                        jpegEnd = i + 2;
                        //  Console.WriteLine($"JPEG end found at:{jpegEnd}");
                        break;
                    }
                }

                if (jpegEnd == -1)
                    throw new Exception("Could not find JPEG end marker (FF D9)");

                int jpegLength = jpegEnd - jpegStart;
                byte[] jpegData = new byte[jpegLength];
                Array.Copy(dg2Bytes, jpegStart, jpegData, 0, jpegLength);

                Console.WriteLine($"Extracted image data length before processing: {jpegData.Length} bytes");

                // Apply Padding Removal BEFORE checking format again
                var pureImgData = RemovePaddingPace(jpegData);

                Console.WriteLine($"Final JPEG length after padding removal: {pureImgData.Length}");
                Console.WriteLine($"Final JPEG header: {BitConverter.ToString(pureImgData.Take(16).ToArray())}");
                Console.WriteLine($"Final JPEG footer: {BitConverter.ToString(pureImgData.Skip(pureImgData.Length - 16).Take(16).ToArray())}");

                if (pureImgData.Length < 100)
                    throw new Exception($"Suspiciously short image data: {pureImgData.Length} bytes");

                // Re-check the image format after padding removal
                string finalDetectedFormat = "JPEG"; // Default
                if (pureImgData.Length > 8)
                {
                    if (pureImgData[0] == 0xFF && pureImgData[1] == 0xD8 && pureImgData[2] == 0xFF && pureImgData[3] == 0xE0)
                    {
                        finalDetectedFormat = "JPEG";
                    }
                    else if (pureImgData[0] == 0x00 && pureImgData[1] == 0x00 && pureImgData[2] == 0x00 &&
                             pureImgData[3] == 0x0C && pureImgData[4] == 0x6A && pureImgData[5] == 0x50)
                    {
                        finalDetectedFormat = "JPEG2000";
                    }
                    else if (pureImgData[0] == 0xFF && pureImgData[1] == 0x4F && pureImgData[2] == 0xFF && pureImgData[3] == 0x51)
                    {
                        finalDetectedFormat = "JPEG2000 Code Stream";
                    }
                }

                Console.WriteLine($"Final detected format after padding removal: {finalDetectedFormat}");

                byte[] finalImageData = pureImgData;

                // Convert only if it’s still a JPEG2000, we doublecheck to make sure we use the correct format
                if (finalDetectedFormat == "JPEG2000" || finalDetectedFormat == "JPEG2000 Code Stream")
                {
                    //  Console.WriteLine("Sending image to API for JPEG conversion...");

                    var converter = new Jpeg2000Converter();
                    byte[] convertedImage = await converter.ConvertJpeg2000ToJpegAsync(pureImgData);

                    //  Console.WriteLine($"Received converted JPEG data length: {convertedImage.Length} bytes");

                    finalImageData = convertedImage;
                }

                var faceInfo2 = new FaceImageInfo
                {
                    ImageData = finalImageData,
                    ImageFormat = "JPEG"
                };

                return faceInfo2;
            }
            catch (Exception ex)
            {
                throw new Exception("Error while parsing DG2 data: " + ex.Message, ex);
            }
        }
     
        private static ASN1Length DecodeASN1Length(byte[] data, int offset)
        {
            if (offset >= data.Length)
            {
                throw new Exception("Invalid offset for ASN.1 length decoding");
            }

            if ((data[offset] & 0x80) == 0)
            {
                // Short form
                return new ASN1Length { Length = data[offset], BytesUsed = 1 };
            }

            // Long form
            int numLengthBytes = data[offset] & 0x7F;
            if (numLengthBytes > 4)
            {
                throw new Exception("Too long ASN.1 length");
            }

            int length = 0;
            for (int i = 0; i < numLengthBytes; i++)
            {
                length = (length << 8) | data[offset + 1 + i];
            }

            return new ASN1Length { Length = length, BytesUsed = 1 + numLengthBytes };
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

        public static async Task<FaceImageInfo> ParseDG2(byte[] rawData, string fileName = "passport_photo")
        {
            try
            {
                //Console.WriteLine($"Starting DG2 parse, total data length: {rawData.Length}");
                //Console.WriteLine($"First 16 bytes: {BitConverter.ToString(rawData.Take(16).ToArray())}");
                //Console.WriteLine($"Last 20 bytes: {BitConverter.ToString(rawData.Skip(rawData.Length - 20).Take(20).ToArray())}");


                // Hitta och validera DG2 data
                int offset = 0;
                while (offset < rawData.Length - 2)
                {
                    // Leta efter biometrisk information tag (7F61)
                    if (rawData[offset] == 0x7F && rawData[offset + 1] == 0x61)
                    {
                        Console.WriteLine($"Found 7F61 tag at offset: {offset}");
                        break;
                    }
                    offset++;
                }

                if (offset >= rawData.Length - 2)
                {
                    throw new Exception("Kunde inte hitta början av biometrisk data");
                }

                // Skippa 7F61 tag
                offset += 2;

                // Läs längden på biometrisk data
                var bioLength = DecodeASN1Length(rawData, offset);
                offset += bioLength.BytesUsed;

                Console.WriteLine($"Biometric data length: {bioLength.Length}");

                // Leta efter bildinformation (5F2E)
                while (offset < rawData.Length - 2)
                {
                    if (rawData[offset] == 0x5F && rawData[offset + 1] == 0x2E)
                    {
                        Console.WriteLine($"Found image tag 5F2E at offset: {offset}");
                        break;
                    }
                    offset++;
                }

                if (offset >= rawData.Length - 2)
                {
                    throw new Exception("Kunde inte hitta bilddata");
                }

                // Skippa 5F2E tag
                offset += 2;

                // Läs längden på bilddata
                var imageLength = DecodeASN1Length(rawData, offset);
                offset += imageLength.BytesUsed;

                Console.WriteLine($"Image data length: {imageLength.Length}");

                int jpegStart = -1;
                for (int i = offset; i < rawData.Length - 1; i++)
                {
                    if (rawData[i] == 0xFF && rawData[i + 1] == 0xD8)
                    {
                        jpegStart = i;
                        Console.WriteLine($"JPEG jpegStart:{jpegStart}");

                        break;
                    }
                }

                if (jpegStart == -1)
                {
                    throw new Exception("Kunde inte hitta JPEG start markör (FF D8)");
                }

                // Hitta JPEG slut
                int jpegEnd = -1;
                for (int i = jpegStart; i < rawData.Length - 1; i++)
                {
                    if (rawData[i] == 0xFF && rawData[i + 1] == 0xD9)
                    {
                        jpegEnd = i + 2; // Inkludera FF D9
                        Console.WriteLine($"JPEG jpegEnd:{jpegEnd}");

                        break;
                    }
                }

                if (jpegEnd == -1)
                {
                    throw new Exception("Kunde inte hitta JPEG slut markör (FF D9)");
                }

                // Beräkna faktisk JPEG storlek och kopiera datan
                int jpegLength = jpegEnd - jpegStart;
                byte[] jpegData = new byte[jpegLength];
                Array.Copy(rawData, jpegStart, jpegData, 0, jpegLength);

                // Extrahera bilddata
                //Console.WriteLine($"Raw image data length before copying rawdata over to jpegData: {rawData.Length}");
                //Console.WriteLine($"First 16 bytes before copying rawdata over to jpegData: {BitConverter.ToString(rawData.Take(16).ToArray())}");
                //Console.WriteLine($"Last 20 bytes before copying rawdata over to jpegData: {BitConverter.ToString(rawData.Skip(rawData.Length - 20).Take(20).ToArray())}");

                //Console.WriteLine($"data length after copying rawdata over to jpegData: {jpegData.Length}");
                //Console.WriteLine($"First 16 bytes after copying rawdata over to jpegData: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
                //Console.WriteLine($"Last 20 bytes after copying rawdata over to jpegData: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 20).Take(20).ToArray())}");


                // Ta bort 80 00 sekvenser
                jpegData = RemovePadding(jpegData);
                const int chunkSize = 100;
                for (int i = 0; i < jpegData.Length; i += chunkSize)
                {
                    int length = Math.Min(chunkSize, jpegData.Length - i);
                    var chunk = new byte[length];
                    Array.Copy(jpegData, i, chunk, 0, length);
                    //Console.WriteLine($"Chunk {i / chunkSize}: {BitConverter.ToString(chunk)}");
                }
                //Console.WriteLine($"Final JPEG length after padding removal: {jpegData.Length}");
                //Console.WriteLine($"Final JPEG header: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
                //Console.WriteLine($"Final JPEG footer: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 16).Take(16).ToArray())}");

                var nopad = RemovePadding2(jpegData);
                Console.WriteLine($"nopad JPEG length after padding removal: {nopad.Length}");

                if (!IsValidJPEG(nopad))
                {
                    throw new Exception("Extraherad data är inte en giltig JPEG");
                }
                if (jpegData.Length < 100)
                {
                    throw new Exception($"Misstänkt kort bilddata: {nopad.Length} bytes");
                }
                var faceInfo = new FaceImageInfo
                {
                    ImageData = nopad,
                    ImageFormat = "JPEG"
                };

                faceInfo.SavedFilePath = await AutoSaveImage(faceInfo, fileName);
                Console.WriteLine($"-------------SAVED PATH: {faceInfo.SavedFilePath}");
                return faceInfo;
            }
            catch (Exception ex)
            {
                throw new Exception("Fel vid parsning av DG2 data: " + ex.Message, ex);
            }
        }

        public static byte[] RemovePadding2(byte[] input)
        {
            List<byte> result = new List<byte>();

            for (int i = 0; i < input.Length; i++)
            {
                // Kolla om vi har hittat början på en padding-sekvens
                if (i <= input.Length - 8 &&  // Se till att vi har nog med bytes kvar att kolla
                    input[i] == 0x80 &&
                    input[i + 1] == 0x00 &&
                    input[i + 2] == 0x00 &&
                    input[i + 3] == 0x00 &&
                    input[i + 4] == 0x00 &&
                    input[i + 5] == 0x00 &&
                    input[i + 6] == 0x00 &&
                    input[i + 7] == 0x00)
                {
                    // Hoppa över padding-sekvensen
                    i += 7;  // +7 eftersom for-loopen kommer lägga till +1
                    continue;
                }

                // Lägg till byte om det inte var del av en padding
                result.Add(input[i]);
            }

            return result.ToArray();
        }

        private static ASN1Length DecodeASN1Length2(byte[] data, int offset)
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

        private static byte[] RemovePadding(byte[] data)
        {
            // Först, hitta den faktiska JPEG-datan
            int startIndex = -1;
            int endIndex = -1;

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
            Console.WriteLine($"Length of data:{data.Length}");
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
            {
                throw new Exception("Kunde inte hitta giltig JPEG-data");
            }

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

        private static async Task<string> AutoSaveImage(FaceImageInfo faceInfo, string fileName)
        {
            try
            {
                // Bygg filnamn
                string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string fullFileName = $"{fileName}_{timestamp}.jpg";

                // Använd MediaStore för att spara bilden
                var context = global::Android.App.Application.Context;
                var resolver = context.ContentResolver;

                ContentValues values = new ContentValues();
                values.Put(IMediaColumns.DisplayName, fullFileName);
                values.Put(IMediaColumns.MimeType, "image/jpeg");
                values.Put(IMediaColumns.RelativePath, DirectoryPictures);

                var imageUri = resolver.Insert(Images.Media.ExternalContentUri, values);

                if (imageUri == null)
                {
                    throw new Exception("Kunde inte skapa URI för att spara bilden.");
                }

                using (var outputStream = resolver.OpenOutputStream(imageUri))
                {
                    if (outputStream == null)
                    {
                        throw new Exception("Kunde inte öppna OutputStream för att spara bilden.");
                    }

                    await outputStream.WriteAsync(faceInfo.ImageData, 0, faceInfo.ImageData.Length);
                }

                Console.WriteLine($"Bilden sparades: {imageUri.Path}");
                return imageUri.Path ?? "Okänd sökväg";
            }
            catch (Exception ex)
            {
                throw new Exception("Kunde inte spara bilden: " + ex.Message, ex);
            }
        }
    }
}
