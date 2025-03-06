using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public class QCCMarker
    {
        // Total segment length (includes 2 bytes for Lqcc, 1 byte for ComponentIndex,
        // 1 byte for Spqcc, and the step size values)
        public ushort Lqcc { get; set; }
        // Component index to which this marker applies
        public byte ComponentIndex { get; set; }
        // Quantization style parameter for this component (Spqcc)
        public byte Spqcc { get; set; }
        // List of quantization step size values (each stored as a 16-bit value)
        public List<ushort> StepSizes { get; set; } = new List<ushort>();

        
    }

    public static class QCCMarkerParser
    {
        public static QCCMarker Parse(BinaryReader reader)
        {
            QCCMarker qcc = new QCCMarker();

            // Read the marker segment length (Lqcc): 2 bytes big-endian
            qcc.Lqcc = ReadUInt16BigEndian(reader);
            // Read the component index (Cqcc): 1 byte
            qcc.ComponentIndex = reader.ReadByte();
            // Read the quantization style for this component (Spqcc): 1 byte
            qcc.Spqcc = reader.ReadByte();

            // The remaining bytes are quantization step sizes.
            // Number of step sizes = (Lqcc - 4) / 2 (each step size is 2 bytes)
            int numSteps = (qcc.Lqcc - 4) / 2;
            for (int i = 0; i < numSteps; i++)
            {
                ushort step = ReadUInt16BigEndian(reader);
                qcc.StepSizes.Add(step);
            }

            return qcc;
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
