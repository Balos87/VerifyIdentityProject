using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public class PaceCommandFormatter
    {
        public static byte[] FormatPublicKeyCommand(byte[] publicKeyX, byte[] publicKeyY)
        {
            // Validera längden
            if (publicKeyX.Length != 48 || publicKeyY.Length != 48)
            {
                throw new ArgumentException($"Public key coordinates must be 48 bytes each. Got X: {publicKeyX.Length}, Y: {publicKeyY.Length}");
            }

            var command = new List<byte>
    {
        0x10,    // CLA med command chaining
        0x86,    // INS (GENERAL AUTHENTICATE)
        0x00,    // P1
        0x00,    // P2
        0x00,    // Lc (fylls i senare)
        0x7C,    // Dynamic Authentication Data tag
        0x00,    // Längd (fylls i senare)
        0x83,    // Ephemeral Public Key tag (ändrat från 0x81)
        0x00     // Längd (fylls i senare)
    };

            // Kombinera public key data
            byte[] encodedPublicKey = new byte[97];  // 0x04 + X + Y
            encodedPublicKey[0] = 0x04;  // Uncompressed point format
            Array.Copy(publicKeyX, 0, encodedPublicKey, 1, 48);
            Array.Copy(publicKeyY, 0, encodedPublicKey, 49, 48);

            // Lägg till data
            command.AddRange(encodedPublicKey);

            // Beräkna och sätt längder
            int dataLength = encodedPublicKey.Length;
            command[8] = (byte)dataLength;              // Längd för public key data
            command[6] = (byte)(dataLength + 2);        // Längd för Dynamic Authentication Data
            command[4] = (byte)(command[6] + 2);        // Total Lc längd

            // Lägg till Le byte
            command.Add(0x00);

            Console.WriteLine($"Data length: {dataLength}");
            Console.WriteLine($"Total command length: {command.Count}");
            Console.WriteLine($"Command: {BitConverter.ToString(command.ToArray())}");

            return command.ToArray();
        }
    }
}
