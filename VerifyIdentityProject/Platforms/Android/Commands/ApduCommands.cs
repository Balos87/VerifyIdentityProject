using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android.Commands
{
    // Command Builder
    public class ApduCommand
    {
        public CLA Class { get; set; }
        public INS Instruction { get; set; }
        public P1 Parameter1 { get; set; }
        public P2 Parameter2 { get; set; }
        public byte[] Data { get; set; } = Array.Empty<byte>();

        public byte[] ToByteArray()
        {
            var apdu = new List<byte>
            {
                (byte)Class,
                (byte)Instruction,
                (byte)Parameter1,
                (byte)Parameter2,
                (byte)Data.Length // Lc
            };

            apdu.AddRange(Data);

            return apdu.ToArray();
        }
    }

    // CLA Enum
    public enum CLA : byte
    {
        SelectFile = 0x00,
        Proprietary = 0x80
    }

    // INS Enum
    public enum INS : byte
    {
        Select = 0xA4,
        ReadBinary = 0xB0,
        UpdateBinary = 0xD6,
        GetChallenge = 0x84
    }

    // P1 Enum
    public enum P1 : byte
    {
        SelectById = 0x04,
        SelectByName = 0x08
    }

    // P2 Enum
    public enum P2 : byte
    {
        FirstOrOnlyOccurrence = 0x0C,
        LastOrOnlyOccurrence = 0x0D
    }

}
