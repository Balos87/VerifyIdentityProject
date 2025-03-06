using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public class QCDMarker
    {
        // Total segment length (includes 2 bytes for Lqcd, 1 byte for Spqcd, and step size values)
        public ushort Lqcd { get; set; }
        // Quantization style parameter (Spqcd)
        public byte Spqcd { get; set; }
        // List of quantization step size values (each stored as a 16-bit value)
        public List<ushort> StepSizes { get; set; } = new List<ushort>();


    }

    public static class QCDMarkerParser
    {
        public static QCDMarker Parse(BinaryReader reader)
        {
            QCDMarker qcd = new QCDMarker();

            // Read the marker segment length (Lqcd): 2 bytes big-endian
            qcd.Lqcd = ReadUInt16BigEndian(reader);
            // Read the quantization style (Spqcd): 1 byte
            qcd.Spqcd = reader.ReadByte();

            // The remaining bytes are quantization step sizes.
            // Number of step sizes = (Lqcd - 3) / 2 (each step size is 2 bytes)
            int numSteps = (qcd.Lqcd - 3) / 2;
            for (int i = 0; i < numSteps; i++)
            {
                ushort step = ReadUInt16BigEndian(reader);
                qcd.StepSizes.Add(step);
            }

            return qcd;
        }

        // Helper method to read a 16-bit unsigned integer in Big-Endian format.
        private static ushort ReadUInt16BigEndian(BinaryReader reader)
        {
            byte[] bytes = reader.ReadBytes(2);
            if (bytes.Length != 2)
                throw new EndOfStreamException("Unable to read 2 bytes for UInt16 value.");
            Array.Reverse(bytes); // Convert from Big-Endian to the system's endianness if necessary.
            return BitConverter.ToUInt16(bytes, 0);
        }
    }
}
