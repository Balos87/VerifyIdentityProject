using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SIZMarker
    {
        // Marker segment length (Lsiz) and Rsiz (capabilities)
        public ushort Lsiz { get; set; }
        public ushort Rsiz { get; set; }

        // Image and grid parameters
        public uint Xsiz { get; set; }
        public uint Ysiz { get; set; }
        public uint XOsiz { get; set; }
        public uint YOsiz { get; set; }

        // Tile parameters
        public uint XTsiz { get; set; }
        public uint YTsiz { get; set; }
        public uint XTOsiz { get; set; }
        public uint YTOsiz { get; set; }

        // Number of components
        public ushort Csiz { get; set; }

        // Per-component information
        public List<Component> Components { get; set; } = new List<Component>();

        public class Component
        {
            // Ssiz: bits per component minus one plus sign flag
            public byte Ssiz { get; set; }
            // Horizontal and vertical separation factors
            public byte XRsiz { get; set; }
            public byte YRsiz { get; set; }
        }


       

    }

    public static class SIZMarkerParser
    {
        public static SIZMarker Parse(BinaryReader reader)
        {
            // Create an instance to hold the parsed data
            SIZMarker siz = new SIZMarker();

            // Read the SIZ marker segment length (Lsiz) – 2 bytes, big-endian.
            siz.Lsiz = ReadUInt16BigEndian(reader);
            // Read Rsiz – 2 bytes
            siz.Rsiz = ReadUInt16BigEndian(reader);

            // Read image and reference grid parameters (each 4 bytes)
            siz.Xsiz = ReadUInt32BigEndian(reader);   // Width of the reference grid
            siz.Ysiz = ReadUInt32BigEndian(reader);   // Height of the reference grid
            siz.XOsiz = ReadUInt32BigEndian(reader);  // Horizontal offset to the image's top-left corner
            siz.YOsiz = ReadUInt32BigEndian(reader);  // Vertical offset to the image's top-left corner

            // Read tile parameters (each 4 bytes)
            siz.XTsiz = ReadUInt32BigEndian(reader);  // Width of a tile
            siz.YTsiz = ReadUInt32BigEndian(reader);  // Height of a tile
            siz.XTOsiz = ReadUInt32BigEndian(reader); // Horizontal offset to the first tile's top-left corner
            siz.YTOsiz = ReadUInt32BigEndian(reader); // Vertical offset to the first tile's top-left corner

            // Read the number of components (Csiz) – 2 bytes
            siz.Csiz = ReadUInt16BigEndian(reader);

            // For each component, read Ssiz (1 byte), XRsiz (1 byte), and YRsiz (1 byte)
            for (int i = 0; i < siz.Csiz; i++)
            {
                SIZMarker.Component comp = new SIZMarker.Component
                {
                    Ssiz = reader.ReadByte(),
                    XRsiz = reader.ReadByte(),
                    YRsiz = reader.ReadByte()
                };
                siz.Components.Add(comp);
            }

            return siz;
        }

        // Helper method to read a 32-bit unsigned integer in Big-Endian format.
        private static uint ReadUInt32BigEndian(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(4);
            if (bytes.Length != 4)
                throw new EndOfStreamException("Unable to read 4 bytes for UInt32 value.");
            Array.Reverse(bytes); // Convert from big-endian to little-endian (if needed)
            return BitConverter.ToUInt32(bytes, 0);
        }

        // Helper method to read a 16-bit unsigned integer in Big-Endian format.
        private static ushort ReadUInt16BigEndian(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(2);
            if (bytes.Length != 2)
                throw new EndOfStreamException("Unable to read 2 bytes for UInt16 value.");
            Array.Reverse(bytes); // Convert from big-endian to little-endian (if needed)
            return BitConverter.ToUInt16(bytes, 0);
        }
    }
}