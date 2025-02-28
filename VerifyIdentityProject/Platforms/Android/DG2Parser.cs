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

// 00-00-00-0C-6A-50-20-20
// FF-4F-FF-51 
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

        // Helper: Check if the file starts with the JP2 signature box.
        // Typically: [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, ...]
        private static bool HasJP2SignatureBox(byte[] data)
        {
            if (data.Length < 12) return false;
            return (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x0C &&
                    data[4] == 0x6A && data[5] == 0x50 && data[6] == 0x20 && data[7] == 0x20);
        }

        public static FaceImageInfo ParseDG2ToJPEG2000(byte[] dg2Bytes, string fileNameBase = "passport_photo")
        {
            //letsgooooooooooooooooooooooooooooooooooooooooooooo
                //----------------------------------------------------------testt
                try
                {

                    Console.WriteLine($"Starting JPEG2000 extraction from DG2, total DG2 length: {dg2Bytes.Length}");
                    byte[] imageBytes = null;

                    Console.WriteLine($"Starting DG2 PACE parse, total data length: {dg2Bytes.Length}");
                    // Hitta och validera DG2 data
                    int offset = 0;
                    while (offset < dg2Bytes.Length - 2)
                    {
                        // Leta efter biometrisk information tag (7F61)
                        if (dg2Bytes[offset] == 0x7F && dg2Bytes[offset + 1] == 0x61)
                        {
                            Console.WriteLine($"Found 7F61 tag at offset: {offset}");
                            break;
                        }
                        offset++;
                    }

                    if (offset >= dg2Bytes.Length - 2)
                        throw new Exception("Kunde inte hitta början av biometrisk data");

                    // Skippa 7F61 tag
                    offset += 2;

                    // Läs längden på biometrisk data
                    var bioLength = DecodeASN1Length(dg2Bytes, offset);
                    offset += bioLength.BytesUsed;

                    Console.WriteLine($"Biometric data length: {bioLength.Length}");

                    // Leta efter bildinformation (5F2E)
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
                        throw new Exception("Kunde inte hitta bilddata");


                    // Skippa 5F2E tag
                    offset += 2;

                    // Läs längden på bilddata
                    var imageLength = DecodeASN1Length(dg2Bytes, offset);
                    offset += imageLength.BytesUsed;

                    Console.WriteLine($"Image data length: {imageLength.Length}");

                    int jpegStart = -1;
                    for (int i = offset; i < dg2Bytes.Length - 1; i++)
                    {
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
                            Console.WriteLine($"JPEG jpegStart:{jpegStart}");

                            break;
                        }
                    }

                    if (jpegStart == -1)
                        throw new Exception("Kunde inte hitta JPEG start markör (FF D8)");

                    // Hitta JPEG slut
                    int jpegEnd = -1;
                    for (int i = jpegStart; i < dg2Bytes.Length - 1; i++)
                    {
                        if (dg2Bytes[i] == 0xFF && dg2Bytes[i + 1] == 0xD9)
                        {
                            jpegEnd = i + 2; // Inkludera FF D9
                            Console.WriteLine($"JPEG jpegEnd:{jpegEnd}");

                            break;
                        }
                    }

                    if (jpegEnd == -1)
                        throw new Exception("Kunde inte hitta JPEG slut markör (FF D9)");

                    // Beräkna faktisk JPEG storlek och kopiera datan
                    int jpegLength = jpegEnd - jpegStart;
                    byte[] jpegData = new byte[jpegLength];
                    Array.Copy(dg2Bytes, jpegStart, jpegData, 0, jpegLength);

                    // Extrahera bilddata
                    Console.WriteLine($"Raw image data length before copying rawdata over to jpegData: {dg2Bytes.Length}");
                    Console.WriteLine($"First 16 bytes before copying rawdata over to jpegData: {BitConverter.ToString(dg2Bytes.Take(16).ToArray())}");
                    Console.WriteLine($"Last 20 bytes before copying rawdata over to jpegData: {BitConverter.ToString(dg2Bytes.Skip(dg2Bytes.Length - 20).Take(20).ToArray())}");

                    Console.WriteLine($"data length after copying rawdata over to jpegData: {jpegData.Length}");
                    Console.WriteLine($"First 16 bytes after copying rawdata over to jpegData: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
                    Console.WriteLine($"Last 20 bytes after copying rawdata over to jpegData: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 20).Take(20).ToArray())}");

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
                    //if (!IsValidJPEG(pureImgData))
                    //    throw new Exception("Extraherad data är inte en giltig JPEG");

                    if (jpegData.Length < 100)
                        throw new Exception($"Misstänkt kort bilddata: {pureImgData.Length} bytes");

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
                    throw new Exception("Fel vid parsning av DG2 data: " + ex.Message, ex);
                }













                ////----------------------------------------------------------testt
                //// 1. Locate the 5F2E tag in DG2 (manual TLV parsing).
                //for (int i = 0; i < dg2Bytes.Length - 1; i++)
                //{
                //    if ((dg2Bytes[i] & 0xFF) == 0x5F && (dg2Bytes[i + 1] & 0xFF) == 0x2E)
                //    {
                //        Console.WriteLine($"Found image tag 5F2E at offset: {i}");
                //        int lengthByte = dg2Bytes[i + 2] & 0xFF;
                //        int dataOffset;
                //        int imageLength;

                //        if (lengthByte <= 0x7F)
                //        {
                //            imageLength = lengthByte;
                //            dataOffset = i + 3;
                //        }
                //        else if (lengthByte == 0x81)
                //        {
                //            imageLength = dg2Bytes[i + 3] & 0xFF;
                //            dataOffset = i + 4;
                //        }
                //        else if (lengthByte == 0x82)
                //        {
                //            imageLength = ((dg2Bytes[i + 3] & 0xFF) << 8) | (dg2Bytes[i + 4] & 0xFF);
                //            dataOffset = i + 5;
                //        }
                //        else
                //        {
                //            throw new Exception("Unsupported length encoding for 5F2E tag.");
                //        }

                //        if (dataOffset + imageLength > dg2Bytes.Length)
                //            throw new Exception("Invalid image length (exceeds DG2 size).");

                //        imageBytes = new byte[imageLength];
                //        Array.Copy(dg2Bytes, dataOffset, imageBytes, 0, imageLength);
                //        break;
                //    }
                //}

                //if (imageBytes == null || imageBytes.Length == 0)
                //    throw new Exception("Could not locate 5F2E image data in DG2.");

                //// 2. Determine if the extracted bytes are JPEG2000.
                //string imageFormatIdentifier = DetermineImageFormat(imageBytes);
                //Console.WriteLine($"Detected image format: {imageFormatIdentifier}");
                //if (imageFormatIdentifier != "JPEG2000_Bitmap" && imageFormatIdentifier != "JPEG2000_Codestream")
                //    throw new Exception("Extracted data is not recognized as JPEG2000.");

                //// 3. Remove any PACE padding from the complete image block.
                //imageBytes = RemovePaddingPace(imageBytes);
                //Console.WriteLine($"Length after removing PACE padding: {imageBytes.Length}");

                //// 4. Locate the JPEG2000 header start.
                //// We'll look for the 8-byte signature "00 00 00 0C 6A 50 20 20".
                //byte[] headerPattern = new byte[] { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20 };
                //int headerIndex = IndexOfSequence(imageBytes, headerPattern);
                //if (headerIndex < 0)
                //    throw new Exception("JPEG2000 header signature not found in image data.");
                //Console.WriteLine($"Found JPEG2000 header at index: {headerIndex}");

                //// 5. Locate the EOC marker (FF D9) after the header.
                //int eocIndex = -1;
                //for (int i = headerIndex; i < imageBytes.Length - 1; i++)
                //{
                //    if (imageBytes[i] == 0xFF && imageBytes[i + 1] == 0xD9)
                //        eocIndex = i;  // keep updating to get the final occurrence
                //}
                //if (eocIndex == -1)
                //{
                //    Console.WriteLine("EOC marker not found in image data. Will append it later.");
                //    eocIndex = imageBytes.Length - 1; // fallback; will be fixed below
                //}
                //else
                //{
                //    Console.WriteLine($"Found EOC marker at index: {eocIndex}");
                //}

                //// 6. Extract the subarray from headerIndex to EOC marker (inclusive).
                //int extractedLength = eocIndex + 2 - headerIndex;
                //byte[] imagePickedWithHeaderAndFooter = new byte[extractedLength];
                //Array.Copy(imageBytes, headerIndex, imagePickedWithHeaderAndFooter, 0, extractedLength);
                //Console.WriteLine($"Extracted image data from header to EOC. Length = {extractedLength}");

                //// 7. Remove any remaining padding from the extracted subarray.
                //byte[] imagePure = RemovePaddingPace(imagePickedWithHeaderAndFooter);
                //Console.WriteLine($"Length after final padding removal: {imagePure.Length}");

                //// 8. Ensure the final data ends with EOC marker.
                //imagePure = EnsureEOCMarker(imagePure);
                //Console.WriteLine($"Final length after ensuring EOC marker: {imagePure.Length}");
                //Console.WriteLine($"Last 20 bytes after ensuring EOC: {BitConverter.ToString(imagePure.Skip(Math.Max(0, imagePure.Length - 20)).Take(20).ToArray())}");

                //// 9. Decide file extension based on JP2 signature box.
                //string extension = ".j2k";  // default for raw codestream
                //if (HasJP2SignatureBox(imagePure))
                //{
                //    extension = ".jp2";
                //    Console.WriteLine("Detected JP2 box-based format. Saving with .jp2 extension.");
                //}
                //else
                //{
                //    Console.WriteLine("No JP2 box found; assuming raw codestream. Saving with .j2k extension.");
                //}

                //// 10. Build the FaceImageInfo object.
                //FaceImageInfo faceInfo = new FaceImageInfo
                //{
                //    ImageData = imagePure,
                //    ImageFormat = "JPEG2000"
                //};

                //// 11. Save the file.
                //faceInfo.SavedFilePath = AutoSaveImage(faceInfo, fileNameBase, extension);
                //Console.WriteLine($"Image saved path: {faceInfo.SavedFilePath}");

                //return faceInfo;
            

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

        // Helper: Truncate at the EOC marker (0xFF 0xD9) from the given data.
        private static byte[] TruncateAtEOC(byte[] data)
        {
            int eocIndex = -1;
            for (int i = 0; i < data.Length - 1; i++)
            {
                if (data[i] == 0xFF && data[i + 1] == 0xD9)
                {
                    eocIndex = i; // update continuously to get the final occurrence
                }
            }
            if (eocIndex != -1 && eocIndex + 1 < data.Length)
            {
                int newLength = eocIndex + 2;
                byte[] truncated = new byte[newLength];
                Array.Copy(data, truncated, newLength);
                Console.WriteLine($"Truncated data at EOC marker. New length = {newLength}");
                return truncated;
            }
            return data;
        }


        // Helper: Ensure that data ends with an EOC marker (0xFF, 0xD9); if not, append it.
        private static byte[] EnsureEOCMarker(byte[] data)
        {
            if (data.Length < 2)
                return data;
            if (data[data.Length - 2] != 0xFF || data[data.Length - 1] != 0xD9)
            {
                byte[] newData = new byte[data.Length + 2];
                Array.Copy(data, newData, data.Length);
                newData[newData.Length - 2] = 0xFF;
                newData[newData.Length - 1] = 0xD9;
                Console.WriteLine("Appended EOC marker to image data.");
                return newData;
            }
            return data;
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
