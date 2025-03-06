using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public class CODMarker
    {
        // Length of the COD marker segment (Lcod)
        public ushort Lcod { get; set; }
        // Coding style flags (Scod)
        public byte Scod { get; set; }
        // Number of decomposition levels (SGcod)
        public byte SGcod { get; set; }

        // Parameters parsed from SPcod (4 bytes)
        // Code-block width exponent (stored as CbW - 2)
        public byte CodeBlockWidthExp { get; set; }
        // Code-block height exponent (stored as CbH - 2)
        public byte CodeBlockHeightExp { get; set; }
        // Code-block style flags
        public byte CodeBlockStyle { get; set; }
        // Transformation indicator (e.g., 0 for reversible, 1 for irreversible)
        public byte TransformationIndicator { get; set; }
        // Number of guard bits (if applicable)
        public byte GuardBits { get; set; }


       

    }

    public static  class CODMarkerParser
    {
        public static CODMarker Parse(BinaryReader reader)
        {
            CODMarker cod = new CODMarker();

            // Read Lcod (segment length) - 2 bytes big-endian.
            cod.Lcod = ReadUInt16BigEndian(reader);

            // Read Scod (1 byte) - coding style flags.
            cod.Scod = reader.ReadByte();

            // Read SGcod (1 byte) - number of decomposition levels.
            cod.SGcod = reader.ReadByte();

            // Read SPcod (4 bytes) - a packed field with several parameters.
            uint spcod = ReadUInt32BigEndian(reader);

            // Extract subfields from SPcod:
            // Bits 0-3: Code-block width exponent (CbW - 2)
            cod.CodeBlockWidthExp = (byte)(spcod & 0xF);
            // Bits 4-7: Code-block height exponent (CbH - 2)
            cod.CodeBlockHeightExp = (byte)((spcod >> 4) & 0xF);
            // Bits 8-15: Code-block style flags
            cod.CodeBlockStyle = (byte)((spcod >> 8) & 0xFF);
            // Bits 16-23: Transformation indicator
            cod.TransformationIndicator = (byte)((spcod >> 16) & 0xFF);
            // Bits 24-31: Guard bits (if used)
            cod.GuardBits = (byte)((spcod >> 24) & 0xFF);

            return cod;
        }

        // Helper method to read a 32-bit unsigned integer in Big-Endian format.
        private static uint ReadUInt32BigEndian(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(4);
            if (bytes.Length != 4)
                throw new EndOfStreamException("Unable to read 4 bytes for UInt32 value.");
            Array.Reverse(bytes); // Convert from big-endian to little-endian if necessary.
            return BitConverter.ToUInt32(bytes, 0);
        }

        // Helper method to read a 16-bit unsigned integer in Big-Endian format.
        private static ushort ReadUInt16BigEndian(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(2);
            if (bytes.Length != 2)
                throw new EndOfStreamException("Unable to read 2 bytes for UInt16 value.");
            Array.Reverse(bytes); // Convert from big-endian to little-endian if necessary.
            return BitConverter.ToUInt16(bytes, 0);
        }
    }
}