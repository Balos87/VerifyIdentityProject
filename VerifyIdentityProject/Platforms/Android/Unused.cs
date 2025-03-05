using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static VerifyIdentityProject.Platforms.Android.DG2Parser;

namespace VerifyIdentityProject.Platforms.Android
{
    class Unused
    {

        //public static byte[] RemovePadding2(byte[] input)
        //{
        //    List<byte> result = new List<byte>();

        //    for (int i = 0; i < input.Length; i++)
        //    {
        //        // Kolla om vi har hittat början på en padding-sekvens
        //        if (i <= input.Length - 8 &&  // Se till att vi har nog med bytes kvar att kolla
        //            input[i] == 0x80 &&
        //            input[i + 1] == 0x00 &&
        //            input[i + 2] == 0x00 &&
        //            input[i + 3] == 0x00 &&
        //            input[i + 4] == 0x00 &&
        //            input[i + 5] == 0x00 &&
        //            input[i + 6] == 0x00 &&
        //            input[i + 7] == 0x00)
        //        {
        //            // Hoppa över padding-sekvensen
        //            i += 7;  // +7 eftersom for-loopen kommer lägga till +1
        //            continue;
        //        }

        //        // Lägg till byte om det inte var del av en padding
        //        result.Add(input[i]);
        //    }

        //    return result.ToArray();
        //}

        //public static FaceImageInfo ParseDG2(byte[] rawData, string fileName = "passport_photo")
        //{
        //    try
        //    {
        //        Console.WriteLine($"Starting DG2 parse, total data length: {rawData.Length}");
        //        Console.WriteLine($"First 16 bytes: {BitConverter.ToString(rawData.Take(16).ToArray())}");
        //        Console.WriteLine($"Last 20 bytes: {BitConverter.ToString(rawData.Skip(rawData.Length - 20).Take(20).ToArray())}");


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
        //        {
        //            throw new Exception("Kunde inte hitta början av biometrisk data");
        //        }

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
        //        {
        //            throw new Exception("Kunde inte hitta bilddata");
        //        }

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
        //        {
        //            throw new Exception("Kunde inte hitta JPEG start markör (FF D8)");
        //        }

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
        //        {
        //            throw new Exception("Kunde inte hitta JPEG slut markör (FF D9)");
        //        }

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


        //        // Ta bort 80 00 sekvenser
        //        jpegData = PickOutJPGDataOnly(jpegData);
        //        const int chunkSize = 100;
        //        for (int i = 0; i < jpegData.Length; i += chunkSize)
        //        {
        //            int length = Math.Min(chunkSize, jpegData.Length - i);
        //            var chunk = new byte[length];
        //            Array.Copy(jpegData, i, chunk, 0, length);
        //            Console.WriteLine($"Chunk {i / chunkSize}: {BitConverter.ToString(chunk)}");
        //        }
        //        Console.WriteLine($"Final JPEG length after padding removal: {jpegData.Length}");
        //        Console.WriteLine($"Final JPEG header: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
        //        Console.WriteLine($"Final JPEG footer: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 16).Take(16).ToArray())}");

        //        var nopad = RemovePadding2(jpegData);
        //        Console.WriteLine($"nopad JPEG length after padding removal: {nopad.Length}");

        //        if (!IsValidJPEG(nopad))
        //        {
        //            throw new Exception("Extraherad data är inte en giltig JPEG");
        //        }
        //        if (jpegData.Length < 100)
        //        {
        //            throw new Exception($"Misstänkt kort bilddata: {nopad.Length} bytes");
        //        }
        //        var faceInfo = new FaceImageInfo
        //        {
        //            ImageData = nopad,
        //            ImageFormat = "JPEG"
        //        };

        //        faceInfo.SavedFilePath = AutoSaveImage(faceInfo, fileName);
        //        Console.WriteLine($"-------------SAVED PATH: {faceInfo.SavedFilePath}");
        //        return faceInfo;
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new Exception("Fel vid parsning av DG2 data: " + ex.Message, ex);
        //    }
        //}



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


        //public static FaceImageInfo ParseDG2Pace(byte[] rawData, string fileName = "passport_photo")
        //{
        //    try
        //    {
        //        Console.WriteLine($"Starting DG2 parse, total data length: {rawData.Length}");

        //        // Locate the biometrics tag (7F61)
        //        int offset = 0;
        //        while (offset < rawData.Length - 2)
        //        {
        //            if (rawData[offset] == 0x7F && rawData[offset + 1] == 0x61)
        //            {
        //                Console.WriteLine($"Found 7F61 tag at offset: {offset}");
        //                break;
        //            }
        //            offset++;
        //        }
        //        if (offset >= rawData.Length - 2)
        //            throw new Exception("Kunde inte hitta början av biometrisk data");

        //        // Skip the 7F61 tag
        //        offset += 2;

        //        // Read biometric data length (ASN.1 encoded)
        //        var bioLength = DecodeASN1Length(rawData, offset);
        //        offset += bioLength.BytesUsed;
        //        Console.WriteLine($"Biometric data length: {bioLength.Length}");

        //        // Locate image tag (5F2E)
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

        //        // Skip the 5F2E tag
        //        offset += 2;

        //        // Read image data length from ASN.1
        //        var imageLength = DecodeASN1Length(rawData, offset);
        //        offset += imageLength.BytesUsed;
        //        Console.WriteLine($"Image data length: {imageLength.Length}");

        //        // Step 1: Extract the entire image block using the decoded ASN.1 length
        //        byte[] imageBlock = new byte[imageLength.Length];
        //        Array.Copy(rawData, offset, imageBlock, 0, imageLength.Length);
        //        Console.WriteLine($"Extracted image block of length: {imageBlock.Length}");

        //        // Step 2: Determine the image format by searching within the image block
        //        string imageFormatIdentifier = DetermineImageFormat(imageBlock);
        //        Console.WriteLine($"Determined image format: {imageFormatIdentifier}");

        //        FaceImageInfo faceInfo = new FaceImageInfo();

        //        if (imageFormatIdentifier == "JPEG")
        //        {
        //            // For JPEG, locate the JPEG start marker (FF D8)
        //            int jpegStartIndex = IndexOfSequence(imageBlock, new byte[] { 0xFF, 0xD8 });
        //            if (jpegStartIndex < 0)
        //                throw new Exception("JPEG header not found in image block.");

        //            // Extract JPEG data from the found index to the end
        //            byte[] jpegData = new byte[imageBlock.Length - jpegStartIndex];
        //            Array.Copy(imageBlock, jpegStartIndex, jpegData, 0, jpegData.Length);

        //            // Remove any known padding from the JPEG data
        //            jpegData = RemovePaddingPace(jpegData);

        //            // Validate that the data is a valid JPEG (must have FF D8 and FF D9 markers)
        //            if (!IsValidJPEG(jpegData))
        //                throw new Exception("Extracted data is not a valid JPEG.");

        //            // Skriv ut första och sista bytes för att verifiera
        //            Console.WriteLine($"First 20 bytes after lower bytes: {BitConverter.ToString(jpegData.Take(20).ToArray())}");
        //            Console.WriteLine($"Last 20 bytes after lower bytes: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 20).Take(20).ToArray())}");


        //            faceInfo.ImageData = jpegData;
        //            faceInfo.ImageFormat = "JPEG";
        //        }
        //        else if (imageFormatIdentifier == "JPEG2000_Bitmap" || imageFormatIdentifier == "JPEG2000_Codestream")
        //        {
        //            // For JPEG2000, assume the ASN.1 length provides the complete image.
        //            // Locate the JPEG2000 header within the image block.
        //            byte[] headerPattern = imageFormatIdentifier == "JPEG2000_Bitmap" ?
        //                                     new byte[] { 0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A } :
        //                                     new byte[] { 0xFF, 0x4F, 0xFF, 0x51 };
        //            int headerIndex = IndexOfSequence(imageBlock, headerPattern);
        //            if (headerIndex < 0)
        //                throw new Exception("JPEG2000 header not found in image block.");

        //            // Extract data from the located header onward
        //            byte[] jp2Data = new byte[imageBlock.Length - headerIndex];
        //            Array.Copy(imageBlock, headerIndex, jp2Data, 0, jp2Data.Length);

        //            // Remove any known padding from the JPEG2000 data
        //            jp2Data = RemovePaddingPace(jp2Data);

        //            // Skriv ut första och sista bytes för att verifiera
        //            Console.WriteLine($"First 20 bytes after lower bytes: {BitConverter.ToString(jp2Data.Take(20).ToArray())}");
        //            Console.WriteLine($"Last 20 bytes after lower bytes: {BitConverter.ToString(jp2Data.Skip(jp2Data.Length - 20).Take(20).ToArray())}");

        //            faceInfo.ImageData = jp2Data;
        //            faceInfo.ImageFormat = "JPEG2000";
        //        }
        //        else
        //        {
        //            throw new Exception("Unsupported image format.");
        //        }

        //        // Save the image using an appropriate extension based on its format.
        //        faceInfo.SavedFilePath = AutoSaveImage(faceInfo, fileName);
        //        Console.WriteLine($"Image saved path: {faceInfo.SavedFilePath}");

        //        return faceInfo;
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new Exception("Fel vid parsning av DG2 data: " + ex.Message, ex);
        //    }
        //}

        //public static FaceImageInfo ExtractJPEG2000FromDG2(byte[] dg2Bytes, string fileName = "passport_photo")
        //{
        //    try
        //    {
        //        Console.WriteLine($"Starting JPEG2000 extraction from DG2, total DG2 length: {dg2Bytes.Length}");
        //        byte[] imageBytes = null;

        //        // Manually search for the image tag (0x5F, 0x2E)
        //        for (int i = 0; i < dg2Bytes.Length - 1; i++)
        //        {
        //            if ((dg2Bytes[i] & 0xFF) == 0x5F && (dg2Bytes[i + 1] & 0xFF) == 0x2E)
        //            {
        //                Console.WriteLine($"Found image tag 5F2E at offset: {i}");
        //                // Read the length byte following the tag
        //                int lengthByte = dg2Bytes[i + 2] & 0xFF;
        //                int dataOffset;
        //                int imageLength;
        //                if (lengthByte <= 0x7F)
        //                {
        //                    // Short form length
        //                    imageLength = lengthByte;
        //                    dataOffset = i + 3;
        //                }
        //                else if (lengthByte == 0x81)
        //                {
        //                    // Next one byte holds the length
        //                    imageLength = dg2Bytes[i + 3] & 0xFF;
        //                    dataOffset = i + 4;
        //                }
        //                else if (lengthByte == 0x82)
        //                {
        //                    // Next two bytes hold the length
        //                    imageLength = ((dg2Bytes[i + 3] & 0xFF) << 8) | (dg2Bytes[i + 4] & 0xFF);
        //                    dataOffset = i + 5;
        //                }
        //                else
        //                {
        //                    throw new Exception("Unsupported length encoding in DG2 image data.");
        //                }

        //                Console.WriteLine($"Extracting JPEG2000 image data of length {imageLength} at offset {dataOffset}");
        //                imageBytes = new byte[imageLength];
        //                Array.Copy(dg2Bytes, dataOffset, imageBytes, 0, imageLength);
        //                break;
        //            }
        //        }

        //        if (imageBytes == null)
        //            throw new Exception("Face image data (tag 5F2E) not found in DG2!");

        //        // Determine the image format based on header patterns.
        //        string imageFormatIdentifier = DetermineImageFormat(imageBytes);
        //        Console.WriteLine($"Determined image format: {imageFormatIdentifier}");

        //        if (imageFormatIdentifier != "JPEG2000_Bitmap" && imageFormatIdentifier != "JPEG2000_Codestream")
        //            throw new Exception("Extracted image is not JPEG2000.");

        //        // Remove any padding from the extracted JPEG2000 data.
        //        imageBytes = RemovePaddingPace(imageBytes);
        //        Console.WriteLine($"Image bytes length after padding removal: {imageBytes.Length}");

        //        // (Optional) Further validations could be added here – for example,
        //        // verifying that the codestream contains the correct markers.

        //        // Build the FaceImageInfo object.
        //        FaceImageInfo faceInfo = new FaceImageInfo();
        //        faceInfo.ImageData = imageBytes;
        //        faceInfo.ImageFormat = "JPEG2000";

        //        // Save the image (AutoSaveImage will pick the correct extension and MIME type)
        //        faceInfo.SavedFilePath = AutoSaveImage(faceInfo, fileName);
        //        Console.WriteLine($"Image saved path: {faceInfo.SavedFilePath}");

        //        return faceInfo;
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new Exception("Error parsing DG2 JPEG2000 data: " + ex.Message, ex);
        //    }
        //}
        //public static FaceImageInfo ParseDG2ToJPEG2000(byte[] dg2Bytes, string fileNameBase = "passport_photo")
        //{
        //    try
        //    {
        //        Console.WriteLine($"Starting JPEG2000 extraction from DG2, total DG2 length: {dg2Bytes.Length}");
        //        byte[] imageBytes = null;

        //        // 1. Locate the 5F2E tag in DG2 (manual TLV parsing).
        //        for (int i = 0; i < dg2Bytes.Length - 1; i++)
        //        {
        //            if ((dg2Bytes[i] & 0xFF) == 0x5F && (dg2Bytes[i + 1] & 0xFF) == 0x2E)
        //            {
        //                Console.WriteLine($"Found image tag 5F2E at offset: {i}");
        //                int lengthByte = dg2Bytes[i + 2] & 0xFF;
        //                int dataOffset;
        //                int imageLength;

        //                // 1.1 Handle short or long form ASN.1 length
        //                if (lengthByte <= 0x7F)
        //                {
        //                    // Short form length
        //                    imageLength = lengthByte;
        //                    dataOffset = i + 3;
        //                }
        //                else if (lengthByte == 0x81)
        //                {
        //                    // Next one byte holds the length
        //                    imageLength = dg2Bytes[i + 3] & 0xFF;
        //                    dataOffset = i + 4;
        //                }
        //                else if (lengthByte == 0x82)
        //                {
        //                    // Next two bytes hold the length
        //                    imageLength = ((dg2Bytes[i + 3] & 0xFF) << 8) | (dg2Bytes[i + 4] & 0xFF);
        //                    dataOffset = i + 5;
        //                }
        //                else
        //                {
        //                    throw new Exception("Unsupported length encoding for 5F2E tag.");
        //                }

        //                if (dataOffset + imageLength > dg2Bytes.Length)
        //                    throw new Exception("Invalid image length (exceeds DG2 size).");

        //                // 1.2 Extract the image bytes
        //                imageBytes = new byte[imageLength];
        //                Array.Copy(dg2Bytes, dataOffset, imageBytes, 0, imageLength);
        //                break;
        //            }
        //        }

        //        if (imageBytes == null || imageBytes.Length == 0)
        //            throw new Exception("Could not locate 5F2E image data in DG2.");

        //        // 2. Determine if the extracted bytes are JPEG2000
        //        string imageFormatIdentifier = DetermineImageFormat(imageBytes);
        //        Console.WriteLine($"Detected image format: {imageFormatIdentifier}");

        //        if (imageFormatIdentifier != "JPEG2000_Bitmap" && imageFormatIdentifier != "JPEG2000_Codestream")
        //        {
        //            throw new Exception("Extracted data is not recognized as JPEG2000.");
        //        }

        //        Console.WriteLine($"First 20 bytes before remove padding: {BitConverter.ToString(imageBytes.Take(20).ToArray())}");
        //        Console.WriteLine($"Last 20 bytes before remove padding: {BitConverter.ToString(imageBytes.Skip(imageBytes.Length - 20).ToArray())}");

        //        // 3. Remove PACE-specific padding if present
        //        imageBytes = RemovePaddingPace(imageBytes);
        //        Console.WriteLine($"Length after removing PACE padding: {imageBytes.Length}");

        //        Console.WriteLine($"First 20 bytes after remove padding: {BitConverter.ToString(imageBytes.Take(20).ToArray())}");
        //        Console.WriteLine($"Last 20 bytes after remove padding: {BitConverter.ToString(imageBytes.Skip(imageBytes.Length - 20).ToArray())}");
        //        // 4. Truncate at EOC marker (0xFF, 0xD9) if found
        //        imageBytes = TruncateAtEOC(imageBytes);
        //        Console.WriteLine($"Length after truncating at EOC (if found): {imageBytes.Length}");

        //        Console.WriteLine($"First 20 bytes after truncation: {BitConverter.ToString(imageBytes.Take(20).ToArray())}");
        //        Console.WriteLine($"Last 20 bytes after truncation: {BitConverter.ToString(imageBytes.Skip(imageBytes.Length - 20).ToArray())}");

        //        Console.WriteLine($"All the bytes: {BitConverter.ToString(imageBytes.ToArray())}");

        //        // 5. Decide file extension based on whether it has a JP2 signature box
        //        // If yes, we use ".jp2", otherwise we use ".j2k"
        //        string extension = ".j2k";  // default
        //        if (HasJP2SignatureBox(imageBytes))
        //        {
        //            extension = ".jp2";
        //            Console.WriteLine("Detected JP2 box-based format. Saving with .jp2 extension.");
        //        }
        //        else
        //        {
        //            Console.WriteLine("No JP2 box found; assuming raw codestream. Saving with .j2k extension.");
        //        }

        //        // 6. Build FaceImageInfo object
        //        FaceImageInfo faceInfo = new FaceImageInfo
        //        {
        //            ImageData = imageBytes,
        //            ImageFormat = "JPEG2000"
        //        };

        //        // 7. Save the file with the chosen extension (AutoSaveImage must accept the extension)
        //        faceInfo.SavedFilePath = AutoSaveImage(faceInfo, fileNameBase, extension);
        //        Console.WriteLine($"Image saved path: {faceInfo.SavedFilePath}");

        //        return faceInfo;
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new Exception("Error parsing DG2 JPEG2000 data: " + ex.Message, ex);
        //    }
        //}

        // Helper: Truncate at the EOC marker (0xFF 0xD9)
        //private static byte[] TruncateAtEOC(byte[] data)
        //{
        //    int eocIndex = -1;
        //    for (int i = 0; i < data.Length - 1; i++)
        //    {
        //        if (data[i] == 0xFF && data[i + 1] == 0xD9)
        //        {
        //            eocIndex = i;
        //        }
        //    }
        //    Console.WriteLine($"Final EOC index found at: {eocIndex}");

        //    if (eocIndex != -1 && eocIndex + 1 < data.Length)
        //    {
        //        int newLength = eocIndex + 2; // Include the EOC marker itself
        //        byte[] truncated = new byte[newLength];
        //        Array.Copy(data, truncated, newLength);
        //        Console.WriteLine($"Truncated data at EOC marker. New length = {newLength}");
        //        return truncated;
        //    }
        //    return data;
        //}

        //// Helper: Check if the file starts with the JP2 signature box
        //// Typically: [0x00,0x00,0x00,0x0C, 0x6A,0x50,0x20,0x20, ...]
        //private static bool HasJP2SignatureBox(byte[] data)
        //{
        //    if (data.Length < 12) return false;
        //    // 00 00 00 0C 6A 50 20 20 ...
        //    return (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x0C &&
        //            data[4] == 0x6A && data[5] == 0x50 && data[6] == 0x20 && data[7] == 0x20);
        //}


        //public static byte[] RemovePaddingPace(byte[] input)
        //{
        //    List<byte> result = new List<byte>();

        //    for (int i = 0; i < input.Length; i++)
        //    {
        //        // Check if we have found the start of a padding sequence (16 bytes: 80 00 ... 00)
        //        if (i <= input.Length - 16 &&
        //            input[i] == 0x80 &&
        //            input[i + 1] == 0x00 &&
        //            input[i + 2] == 0x00 &&
        //            input[i + 3] == 0x00 &&
        //            input[i + 4] == 0x00 &&
        //            input[i + 5] == 0x00 &&
        //            input[i + 6] == 0x00 &&
        //            input[i + 7] == 0x00 &&
        //            input[i + 8] == 0x00 &&
        //            input[i + 9] == 0x00 &&
        //            input[i + 10] == 0x00 &&
        //            input[i + 11] == 0x00 &&
        //            input[i + 12] == 0x00 &&
        //            input[i + 13] == 0x00 &&
        //            input[i + 14] == 0x00 &&
        //            input[i + 15] == 0x00)
        //        {
        //            // Skip the padding sequence (advance index by 15, since the loop will add 1)
        //            i += 15;
        //            continue;
        //        }

        //        // Add the byte if it is not part of a padding sequence
        //        result.Add(input[i]);
        //    }

        //    return result.ToArray();
        //}
        //private static bool IsPaddingBlock(byte[] input, int index)
        //{
        //    // Ensure we have 16 bytes available
        //    if (index > input.Length - 16)
        //        return false;

        //    // Check that the block is exactly: 0x80 followed by fifteen 0x00 bytes.
        //    if (input[index] != 0x80)
        //        return false;

        //    for (int j = 1; j < 16; j++)
        //    {
        //        if (input[index + j] != 0x00)
        //            return false;
        //    }
        //    return true;
        //}

        //public static byte[] RemovePaddingPace(byte[] input)
        //{
        //    List<byte> result = new List<byte>();

        //    for (int i = 0; i < input.Length; i++)
        //    {
        //        if (IsPaddingBlock(input, i))
        //        {
        //            // Log the skipped block if needed:
        //            // Console.WriteLine("Skipping padding block at index " + i);
        //            i += 15; // Skip the 16 bytes (current byte + next 15)
        //            continue;
        //        }
        //        result.Add(input[i]);
        //    }

        //    return result.ToArray();
        //}

        //private static ASN1Length DecodeASN1Length(byte[] data, int offset)
        //{
        //    if (offset >= data.Length)
        //    {
        //        throw new Exception("Ogiltig offset för ASN.1 längd-avkodning");
        //    }

        //    if ((data[offset] & 0x80) == 0)
        //    {
        //        // Kort form
        //        return new ASN1Length { Length = data[offset], BytesUsed = 1 };
        //    }

        //    // Lång form
        //    int numLengthBytes = data[offset] & 0x7F;
        //    if (numLengthBytes > 4)
        //    {
        //        throw new Exception("För lång ASN.1 längd");
        //    }

        //    int length = 0;
        //    for (int i = 0; i < numLengthBytes; i++)
        //    {
        //        length = (length << 8) | data[offset + 1 + i];
        //    }

        //    return new ASN1Length { Length = length, BytesUsed = 1 + numLengthBytes };
        //}


        //private static string AutoSaveImage(FaceImageInfo faceInfo, string fileName)
        //{
        //    try
        //    {
        //        // Build file name with timestamp
        //        string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        //        // Set defaults for JPEG
        //        string extension = "jpg";
        //        string mimeType = "image/jpeg";

        //        // If the image is JPEG2000, adjust the extension and MIME type.
        //        if (faceInfo.ImageFormat == "JPEG2000")
        //        {
        //            extension = "jp2";
        //            mimeType = "image/jp2";
        //        }

        //        string fullFileName = $"{fileName}_{timestamp}.{extension}";

        //        // Use MediaStore to save the image
        //        var context = global::Android.App.Application.Context;
        //        var resolver = context.ContentResolver;

        //        ContentValues values = new ContentValues();
        //        values.Put(IMediaColumns.DisplayName, fullFileName);
        //        values.Put(IMediaColumns.MimeType, mimeType);
        //        values.Put(IMediaColumns.RelativePath, DirectoryPictures);

        //        var imageUri = resolver.Insert(Images.Media.ExternalContentUri, values);

        //        if (imageUri == null)
        //            throw new Exception("Kunde inte skapa URI för att spara bilden.");

        //        using (var outputStream = resolver.OpenOutputStream(imageUri))
        //        {
        //            if (outputStream == null)
        //                throw new Exception("Kunde inte öppna OutputStream för att spara bilden.");

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
    }
}
