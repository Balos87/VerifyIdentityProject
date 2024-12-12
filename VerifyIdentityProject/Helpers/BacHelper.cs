using System.Security.Cryptography;
using System.Text;

namespace VerifyIdentityProject.Helpers;
public static class BacHelper
{
    public static (byte[] KEnc, byte[] KMac) GenerateBacKeys(string mrzData)
    {
        // Compute SHA-1 hash of MRZ data
        byte[] sha1Hash;
        using (SHA1 sha1 = SHA1.Create())
        {
            sha1Hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(mrzData));
        }
        Console.WriteLine($"Hash MRZ: {BitConverter.ToString(sha1Hash)}");

        // Use the first 16 bytes of the hash as Kseed
        byte[] kseed = { 0x23, 0x9A, 0xB9, 0xCB, 0x28, 0x2D, 0xAF, 0x66, 0x23, 0x1D, 0xC5, 0xA4, 0xDF, 0x6B, 0xFB, 0xAE };
        //byte[] kseed = new byte[16];
        //Array.Copy(sha1Hash, kseed, 16);
        Console.WriteLine($"kseed16: {BitConverter.ToString(kseed)}");

        // Generate KEnc and KMac
        byte[] kenc = DeriveKey(kseed, 1); // Counter = 1
        byte[] kmac = DeriveKey(kseed, 2); // Counter = 2

        // Print results
        Console.WriteLine("KEnc: " + BitConverter.ToString(kenc).Replace("-", "").ToLower());
        Console.WriteLine("KMac: " + BitConverter.ToString(kmac).Replace("-", "").ToLower());

        byte[] kencParitet = AdjustParityBits(kenc);
        byte[] kmacParitet = AdjustParityBits(kmac);

        Console.WriteLine("kencParitet: " + BitConverter.ToString(kencParitet).Replace("-", "").ToLower());
        Console.WriteLine("kmacParitet: " + BitConverter.ToString(kmacParitet).Replace("-", "").ToLower());


        static byte[] AdjustParityBits(byte[] key)
        {
            byte[] adjustedKey = new byte[key.Length];

            for (int i = 0; i < key.Length; i++)
            {
                byte currentByte = key[i];
                byte newByte = 0;

                // Kolla varje bit i byten
                for (int bit = 0; bit < 8; bit++)
                {
                    bool bitIsSet = (currentByte & (1 << bit)) != 0;
                    newByte |= (byte)((bitIsSet ? 1 : 0) << bit);
                }

                // Se till att antalet 1-bitar är udda
                if (CountSetBits(newByte) % 2 == 0)
                {
                    newByte |= 1;  // Ändra sista biten för att göra det udda
                }

                adjustedKey[i] = newByte;
            }
            return adjustedKey;
        }
        static int CountSetBits(byte b)
        {
            int count = 0;
            while (b != 0)
            {
                count += b & 1;
                b >>= 1;
            }
            return count;
        }

        static byte[] DeriveKey(byte[] kseed, int counter)
        {
            // Convert counter to a 4-byte big-endian array
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }

            // Concatenate Kseed and counter
            byte[] data = new byte[kseed.Length + counterBytes.Length];
            Buffer.BlockCopy(kseed, 0, data, 0, kseed.Length);
            Buffer.BlockCopy(counterBytes, 0, data, kseed.Length, counterBytes.Length);

            // Compute SHA-1 hash of the concatenated data
            byte[] derivedHash;
            using (SHA1 sha1 = SHA1.Create())
            {
                derivedHash = sha1.ComputeHash(data);
            }

            // Return the first 16 bytes of the hash
            byte[] key = new byte[16];
            Array.Copy(derivedHash, key, 16);
            return key;
        }
        return (kenc, kmac);
    }

}
