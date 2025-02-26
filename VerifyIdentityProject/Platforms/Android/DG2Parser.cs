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

        public static FaceImageInfo ParseDG2(byte[] rawData, string fileName = "passport_photo")
        {
            try
            {
                Console.WriteLine($"Starting DG2 parse, total data length: {rawData.Length}");
                Console.WriteLine($"First 16 bytes: {BitConverter.ToString(rawData.Take(16).ToArray())}");
                Console.WriteLine($"Last 20 bytes: {BitConverter.ToString(rawData.Skip(rawData.Length - 20).Take(20).ToArray())}");


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
                Console.WriteLine($"Raw image data length before copying rawdata over to jpegData: {rawData.Length}");
                Console.WriteLine($"First 16 bytes before copying rawdata over to jpegData: {BitConverter.ToString(rawData.Take(16).ToArray())}");
                Console.WriteLine($"Last 20 bytes before copying rawdata over to jpegData: {BitConverter.ToString(rawData.Skip(rawData.Length - 20).Take(20).ToArray())}");

                Console.WriteLine($"data length after copying rawdata over to jpegData: {jpegData.Length}");
                Console.WriteLine($"First 16 bytes after copying rawdata over to jpegData: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
                Console.WriteLine($"Last 20 bytes after copying rawdata over to jpegData: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 20).Take(20).ToArray())}");


                // Ta bort 80 00 sekvenser
                jpegData = PickOutJPGDataOnly(jpegData);
                const int chunkSize = 100;
                for (int i = 0; i < jpegData.Length; i += chunkSize)
                {
                    int length = Math.Min(chunkSize, jpegData.Length - i);
                    var chunk = new byte[length];
                    Array.Copy(jpegData, i, chunk, 0, length);
                    Console.WriteLine($"Chunk {i / chunkSize}: {BitConverter.ToString(chunk)}");
                }
                Console.WriteLine($"Final JPEG length after padding removal: {jpegData.Length}");
                Console.WriteLine($"Final JPEG header: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
                Console.WriteLine($"Final JPEG footer: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 16).Take(16).ToArray())}");

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

                faceInfo.SavedFilePath = AutoSaveImage(faceInfo, fileName);
                Console.WriteLine($"-------------SAVED PATH: {faceInfo.SavedFilePath}");
                return faceInfo;
            }
            catch (Exception ex)
            {
                throw new Exception("Fel vid parsning av DG2 data: " + ex.Message, ex);
            }
        }

        private static int IndexOfSequence(byte[] data, byte[] pattern)
        {
            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                    return i;
            }
            return -1;
        }

        private static string DetermineImageFormat(byte[] data)
        {
            // Define header patterns
            byte[] jpegHeader = new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 };
            byte[] jpeg2000BitmapHeader = new byte[] { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A };
            byte[] jpeg2000CodestreamHeader = new byte[] { 0xFF, 0x4F, 0xFF, 0x51 };

            // Search for each header within the image block
            int indexJPEG = IndexOfSequence(data, jpegHeader);
            int indexJPEG2000Bitmap = IndexOfSequence(data, jpeg2000BitmapHeader);
            int indexJPEG2000Codestream = IndexOfSequence(data, jpeg2000CodestreamHeader);

            // Determine which header appears first (if any)
            int minIndex = int.MaxValue;
            string format = null;
            if (indexJPEG >= 0 && indexJPEG < minIndex)
            {
                minIndex = indexJPEG;
                format = "JPEG";
            }
            if (indexJPEG2000Bitmap >= 0 && indexJPEG2000Bitmap < minIndex)
            {
                minIndex = indexJPEG2000Bitmap;
                format = "JPEG2000_Bitmap";
            }
            if (indexJPEG2000Codestream >= 0 && indexJPEG2000Codestream < minIndex)
            {
                minIndex = indexJPEG2000Codestream;
                format = "JPEG2000_Codestream";
            }

            if (format == null)
                throw new Exception("Unknown image header format");

            Console.WriteLine($"Found {format} header at index: {minIndex}");
            return format;
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

        public static FaceImageInfo ParseDG2Pace(byte[] rawData, string fileName = "passport_photo")
        {
            try
            {
                Console.WriteLine($"Starting DG2 parse, total data length: {rawData.Length}");

                // Locate the biometrics tag (7F61)
                int offset = 0;
                while (offset < rawData.Length - 2)
                {
                    if (rawData[offset] == 0x7F && rawData[offset + 1] == 0x61)
                    {
                        Console.WriteLine($"Found 7F61 tag at offset: {offset}");
                        break;
                    }
                    offset++;
                }
                if (offset >= rawData.Length - 2)
                    throw new Exception("Kunde inte hitta början av biometrisk data");

                // Skip the 7F61 tag
                offset += 2;

                // Read biometric data length (ASN.1 encoded)
                var bioLength = DecodeASN1Length(rawData, offset);
                offset += bioLength.BytesUsed;
                Console.WriteLine($"Biometric data length: {bioLength.Length}");

                // Locate image tag (5F2E)
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
                    throw new Exception("Kunde inte hitta bilddata");

                // Skip the 5F2E tag
                offset += 2;

                // Read image data length from ASN.1
                var imageLength = DecodeASN1Length(rawData, offset);
                offset += imageLength.BytesUsed;
                Console.WriteLine($"Image data length: {imageLength.Length}");

                // Step 1: Extract the entire image block using the decoded ASN.1 length
                byte[] imageBlock = new byte[imageLength.Length];
                Array.Copy(rawData, offset, imageBlock, 0, imageLength.Length);
                Console.WriteLine($"Extracted image block of length: {imageBlock.Length}");

                // Step 2: Determine the image format by searching within the image block
                string imageFormatIdentifier = DetermineImageFormat(imageBlock);
                Console.WriteLine($"Determined image format: {imageFormatIdentifier}");

                FaceImageInfo faceInfo = new FaceImageInfo();

                if (imageFormatIdentifier == "JPEG")
                {
                    // For JPEG, locate the JPEG start marker (FF D8)
                    int jpegStartIndex = IndexOfSequence(imageBlock, new byte[] { 0xFF, 0xD8 });
                    if (jpegStartIndex < 0)
                        throw new Exception("JPEG header not found in image block.");

                    // Extract JPEG data from the found index to the end
                    byte[] jpegData = new byte[imageBlock.Length - jpegStartIndex];
                    Array.Copy(imageBlock, jpegStartIndex, jpegData, 0, jpegData.Length);

                    // Optionally remove any known padding
                    jpegData = RemovePaddingPace(jpegData);

                    // Validate that the data is a valid JPEG (must have FF D8 and FF D9 markers)
                    if (!IsValidJPEG(jpegData))
                        throw new Exception("Extracted data is not a valid JPEG.");

                    faceInfo.ImageData = jpegData;
                    faceInfo.ImageFormat = "JPEG";
                }
                else if (imageFormatIdentifier == "JPEG2000_Bitmap" || imageFormatIdentifier == "JPEG2000_Codestream")
                {
                    // For JPEG2000, we assume the ASN.1 length provides the complete image.
                    // Locate the JPEG2000 header within the image block.
                    byte[] headerPattern = imageFormatIdentifier == "JPEG2000_Bitmap" ?
                                             new byte[] { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A } :
                                             new byte[] { 0xFF, 0x4F, 0xFF, 0x51 };
                    int headerIndex = IndexOfSequence(imageBlock, headerPattern);
                    if (headerIndex < 0)
                        throw new Exception("JPEG2000 header not found in image block.");

                    // Extract data from the located header onward
                    byte[] jp2Data = new byte[imageBlock.Length - headerIndex];
                    Array.Copy(imageBlock, headerIndex, jp2Data, 0, jp2Data.Length);

                    // (Optional) Further processing for JPEG2000 can be added here.
                    faceInfo.ImageData = jp2Data;
                    faceInfo.ImageFormat = "JPEG2000";
                }
                else
                {
                    throw new Exception("Unsupported image format.");
                }

                // Save the image using an appropriate extension based on its format.
                faceInfo.SavedFilePath = AutoSaveImage(faceInfo, fileName);
                Console.WriteLine($"Image saved path: {faceInfo.SavedFilePath}");

                return faceInfo;
            }
            catch (Exception ex)
            {
                throw new Exception("Fel vid parsning av DG2 data: " + ex.Message, ex);
            }
        }




        //public static byte[] ParseDG2Pace(byte[] rawData, string fileName = "passport_photo")
        //{
        //    try
        //    {
        //        Console.WriteLine($"Starting DG2 parse, total data length: {rawData.Length}");
        //        // Hitta och validera DG2 data
        //        int offset = 0;
        //        while (offset < rawData.Length - 2)
        //        {
        //            // Leta efter biometrisk information tag (7F61)
        //            if (rawData[offset] == 0x7F && rawData[offset + 1] == 0x61)
        //            {
        //                Console.WriteLine($"Found 7F61 tag at offset: {offset}");
        //                break;
        //            }
        //            offset++;
        //        }

        //        if (offset >= rawData.Length - 2)
        //            throw new Exception("Kunde inte hitta början av biometrisk data");

        //        // Skippa 7F61 tag
        //        offset += 2;

        //        // Läs längden på biometrisk data
        //        var bioLength = DecodeASN1Length(rawData, offset);
        //        offset += bioLength.BytesUsed;

        //        Console.WriteLine($"Biometric data length: {bioLength.Length}");

        //        // Leta efter bildinformation (5F2E)
        //        while (offset < rawData.Length - 2)
        //        {
        //            if (rawData[offset] == 0x5F && rawData[offset + 1] == 0x2E)
        //            {
        //                Console.WriteLine($"Found image tag 5F2E at offset: {offset}");
        //                break;
        //            }
        //            offset++;
        //        }

        //        if (offset >= rawData.Length - 2)
        //            throw new Exception("Kunde inte hitta bilddata");


        //        // Skippa 5F2E tag
        //        offset += 2;

        //        // Läs längden på bilddata
        //        var imageLength = DecodeASN1Length(rawData, offset);
        //        offset += imageLength.BytesUsed;

        //        Console.WriteLine($"Image data length: {imageLength.Length}");

        //        int jpegStart = -1;
        //        for (int i = offset; i < rawData.Length - 1; i++)
        //        {
        //            if (rawData[i] == 0xFF && rawData[i + 1] == 0xD8)
        //            {
        //                jpegStart = i;
        //                Console.WriteLine($"JPEG jpegStart:{jpegStart}");

        //                break;
        //            }
        //        }

        //        if (jpegStart == -1)
        //            throw new Exception("Kunde inte hitta JPEG start markör (FF D8)");

        //        // Hitta JPEG slut
        //        int jpegEnd = -1;
        //        for (int i = jpegStart; i < rawData.Length - 1; i++)
        //        {
        //            if (rawData[i] == 0xFF && rawData[i + 1] == 0xD9)
        //            {
        //                jpegEnd = i + 2; // Inkludera FF D9
        //                Console.WriteLine($"JPEG jpegEnd:{jpegEnd}");

        //                break;
        //            }
        //        }

        //        if (jpegEnd == -1)
        //            throw new Exception("Kunde inte hitta JPEG slut markör (FF D9)");

        //        // Beräkna faktisk JPEG storlek och kopiera datan
        //        int jpegLength = jpegEnd - jpegStart;
        //        byte[] jpegData = new byte[jpegLength];
        //        Array.Copy(rawData, jpegStart, jpegData, 0, jpegLength);

        //        // Extrahera bilddata
        //        Console.WriteLine($"Raw image data length before copying rawdata over to jpegData: {rawData.Length}");
        //        Console.WriteLine($"First 16 bytes before copying rawdata over to jpegData: {BitConverter.ToString(rawData.Take(16).ToArray())}");
        //        Console.WriteLine($"Last 20 bytes before copying rawdata over to jpegData: {BitConverter.ToString(rawData.Skip(rawData.Length - 20).Take(20).ToArray())}");

        //        Console.WriteLine($"data length after copying rawdata over to jpegData: {jpegData.Length}");
        //        Console.WriteLine($"First 16 bytes after copying rawdata over to jpegData: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
        //        Console.WriteLine($"Last 20 bytes after copying rawdata over to jpegData: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 20).Take(20).ToArray())}");

        //        const int chunkSize = 100;
        //        for (int i = 0; i < jpegData.Length; i += chunkSize)
        //        {
        //            int length = Math.Min(chunkSize, jpegData.Length - i);
        //            var chunk = new byte[length];
        //            Array.Copy(jpegData, i, chunk, 0, length);
        //            //Console.WriteLine($"Chunk {i / chunkSize}: {BitConverter.ToString(chunk)}");
        //        }
        //        Console.WriteLine($"Final JPEG length after padding removal: {jpegData.Length}");
        //        Console.WriteLine($"Final JPEG header: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
        //        Console.WriteLine($"Final JPEG footer: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 16).Take(16).ToArray())}");

        //        var pureImgData = RemovePaddingPace(jpegData);
        //        Console.WriteLine($"nopad JPEG length after padding removal: {pureImgData.Length}");

        //        if (!IsValidJPEG(pureImgData))
        //            throw new Exception("Extraherad data är inte en giltig JPEG");

        //        if (jpegData.Length < 100)
        //            throw new Exception($"Misstänkt kort bilddata: {pureImgData.Length} bytes");

        //        var faceInfo = new FaceImageInfo
        //        {
        //            ImageData = pureImgData,
        //            ImageFormat = "JPEG"
        //        };

        //        faceInfo.SavedFilePath = AutoSaveImage(faceInfo, fileName);
        //        Console.WriteLine($"Image saved path: {faceInfo.SavedFilePath}");
        //        return pureImgData;
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new Exception("Fel vid parsning av DG2 data: " + ex.Message, ex);
        //    }
        //}

        public static byte[] RemovePaddingPace(byte[] input)
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
                    // Hoppa över padding-sekvensen
                    i += 15;  // +7 eftersom for-loopen kommer lägga till +1
                    continue;
                }

                // Lägg till byte om det inte var del av en padding
                result.Add(input[i]);
            }

            return result.ToArray();
        }

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

        private static string AutoSaveImage(FaceImageInfo faceInfo, string fileName)
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
                    throw new Exception("Kunde inte skapa URI för att spara bilden.");

                using (var outputStream = resolver.OpenOutputStream(imageUri))
                {
                    if (outputStream == null)
                    {
                        throw new Exception("Kunde inte öppna OutputStream för att spara bilden.");
                    }

                    outputStream.Write(faceInfo.ImageData, 0, faceInfo.ImageData.Length);
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
