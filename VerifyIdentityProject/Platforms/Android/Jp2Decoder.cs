using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace VerifyIdentityProject.Platforms.Android
{
    public class Jp2Decoder
    {
        public (byte[], int, int) ParseJp2(byte[] jp2Data)
        {
            using (MemoryStream ms = new MemoryStream(jp2Data))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                int width = 0;
                int height = 0;

                while (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    long boxStart = reader.BaseStream.Position;
                    uint boxLength = ReadUInt32BigEndian(reader);
                    string boxType = Encoding.ASCII.GetString(reader.ReadBytes(4));

                    Console.WriteLine($"Box Type: {boxType}, Length: {boxLength}");

                    if (boxType == "jp2h") // JP2 Header Box
                    {
                        long headerEnd = reader.BaseStream.Position + (boxLength - 8);
                        while (reader.BaseStream.Position < headerEnd)
                        {
                            uint subBoxLength = ReadUInt32BigEndian(reader);
                            string subBoxType = Encoding.ASCII.GetString(reader.ReadBytes(4));

                            if (subBoxType == "ihdr") // Image Header Box
                            {
                                height = (int)ReadUInt32BigEndian(reader);
                                width = (int)ReadUInt32BigEndian(reader);
                                Console.WriteLine($"Extracted Width: {width}, Height: {height}");
                            }
                            else
                            {
                                reader.BaseStream.Seek(subBoxLength - 8, SeekOrigin.Current);
                            }
                        }
                    }

                    if (boxType == "jp2c") // Codestream Box (Image Data)
                    {
                        Console.WriteLine("Found JP2 codestream!");
                        byte[] codestream = reader.ReadBytes((int)(boxLength - 8));
                        byte[] decodedPixels = DecodeCodestream(codestream, width, height);
                        return (decodedPixels, width, height); // Return raw pixels with size
                    }
                    else
                    {
                        reader.BaseStream.Seek(boxStart + boxLength, SeekOrigin.Begin);
                    }
                }
            }

            return (null, 0, 0); // Return null if image data not found
        }



        private uint ReadUInt32BigEndian(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(4);
            Array.Reverse(bytes); // Convert to Big-Endian
            return BitConverter.ToUInt32(bytes, 0);
        }

        private byte[] DecodeCodestream(byte[] codestream, int width, int height)
        {
            using (MemoryStream ms = new MemoryStream(codestream))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                {
                    ushort marker = ReadUInt16BigEndian(reader);

                    switch (marker)
                    {
                        case 0xFF4F: // SOC (Start of Codestream)
                            Console.WriteLine("Start of Codestream");
                            break;

                        case 0xFF51: // SIZ (Size marker)
                            Console.WriteLine("SIZ Marker: Image size & component info");

                            ushort sizLength = ReadUInt16BigEndian(reader); // Read the segment length
                            Console.WriteLine($"SIZ Length: {sizLength} bytes");

                            if (sizLength < 2 || sizLength > reader.BaseStream.Length - reader.BaseStream.Position)
                            {
                                Console.WriteLine($"Invalid SIZ length: {sizLength}, skipping remaining data...");
                                return null;
                            }

                            reader.BaseStream.Seek(sizLength - 2, SeekOrigin.Current); // Skip SIZ segment
                            break;


                        case 0xFF52: // COD (Coding Style Default)
                            Console.WriteLine("COD Marker: Coding Style");
                            SkipVariableLengthSegment(reader);
                            break;

                        case 0xFF5C: // QCD (Quantization Default)
                            Console.WriteLine("QCD Marker: Quantization Default");
                            SkipVariableLengthSegment(reader);
                            break;

                        case 0xFF5D: // QCC (Quantization for Components)
                            Console.WriteLine("QCC Marker: Quantization for Components");
                            SkipVariableLengthSegment(reader);
                            break;

                        case 0xFF90: // SOT (Start of Tile)
                            Console.WriteLine("Start of Tile");
                            SkipVariableLengthSegment(reader);
                            break;

                        case 0xFF93: // SOD (Start of Data)
                            Console.WriteLine("Start of Image Data");
                            byte[] imageData = reader.ReadBytes((int)(reader.BaseStream.Length - reader.BaseStream.Position));
                            return DecodeWavelet(imageData, width, height);

                        case 0xFFD9: // EOC (End of Codestream)
                            Console.WriteLine("End of Codestream");
                            return null;

                        default:
                            // If we encounter an unknown marker, skip it safely
                            if ((marker & 0xFF00) == 0xFF00) // Ensures it's a valid JP2 marker
                            {
                                Console.WriteLine($"Skipping unknown marker: 0x{marker:X}");
                                SkipVariableLengthSegment(reader);
                            }
                            else
                            {
                                Console.WriteLine($"Unexpected data at: {reader.BaseStream.Position} -> 0x{marker:X}");
                            }
                            break;
                    }
                }
            }
            return null;
        }


        private void SkipBytes(BinaryReader reader, int byteCount)
        {
            reader.BaseStream.Seek(byteCount, SeekOrigin.Current);
        }
        private void SkipVariableLengthSegment(BinaryReader reader)
        {
            ushort segmentLength = ReadUInt16BigEndian(reader);
            if (segmentLength < 2 || segmentLength > reader.BaseStream.Length - reader.BaseStream.Position)
            {
                Console.WriteLine($"Invalid segment length: {segmentLength}, skipping remaining data...");
                return; // Prevents reading past valid data
            }
            reader.BaseStream.Seek(segmentLength - 2, SeekOrigin.Current); // -2 accounts for length field
        }




        private ushort ReadUInt16BigEndian(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(2);
            Array.Reverse(bytes); // Convert to Big-Endian
            return BitConverter.ToUInt16(bytes, 0);
        }

        private byte[] DecodeWavelet(byte[] imageData, int width, int height)
        {
            Console.WriteLine("Applying Inverse Wavelet Transform...");

            byte[] decodedPixels = new byte[width * height * 3]; // RGB

            // Placeholder for inverse Haar Wavelet Transform
            int halfWidth = width / 2;
            int halfHeight = height / 2;

            for (int y = 0; y < halfHeight; y++)
            {
                for (int x = 0; x < halfWidth; x++)
                {
                    int lowIndex = (y * width) + x;
                    int highIndex = lowIndex + halfWidth;
                    int lowValue = imageData[lowIndex];
                    int highValue = imageData[highIndex];

                    decodedPixels[lowIndex] = (byte)(lowValue + highValue / 2);
                    decodedPixels[highIndex] = (byte)(lowValue - highValue / 2);
                }
            }

            Console.WriteLine("Wavelet Transform Complete.");
            return decodedPixels;
        }



    }

}
