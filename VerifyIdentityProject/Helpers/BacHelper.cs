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
        //byte[] kseed = { 0x23, 0x9A, 0xB9, 0xCB, 0x28, 0x2D, 0xAF, 0x66, 0x23, 0x1D, 0xC5, 0xA4, 0xDF, 0x6B, 0xFB, 0xAE };
        byte[] kseed = new byte[16];
        Array.Copy(sha1Hash, kseed, 16);
        Console.WriteLine($"kseed16: {BitConverter.ToString(kseed)}");

        // Generate KEnc and KMac
        byte[] kenc = DeriveKey(kseed, 1); // Counter = 1
        byte[] kmac = DeriveKey(kseed, 2); // Counter = 2

        // Print results
        Console.WriteLine("KEnc: " + BitConverter.ToString(kenc).Replace("-", "").ToUpper());
        Console.WriteLine("KMac: " + BitConverter.ToString(kmac).Replace("-", "").ToUpper());

        byte[] kencParitet = AdjustAndSplitKey(kenc);
        byte[] kmacParitet = AdjustAndSplitKey(kmac);

        Console.WriteLine("kencParitet: " + BitConverter.ToString(kencParitet).Replace("-", "").ToUpper());
        Console.WriteLine("kmacParitet: " + BitConverter.ToString(kmacParitet).Replace("-", "").ToUpper());

        return (kencParitet, kmacParitet);
    }



    static byte[] AdjustAndSplitKey(byte[] key)
    {
        if (key.Length != 16)
            throw new ArgumentException("Key must be 16 bytes long for 3DES");

        // Dela nyckeln i två delar
        byte[] KaPrime = key.Take(8).ToArray();  // Första 8 bytes
        byte[] KbPrime = key.Skip(8).Take(8).ToArray();  // Sista 8 bytes

        // Justera paritetsbitarna
        byte[] Ka = AdjustParityBitsExact(KaPrime);
        byte[] Kb = AdjustParityBitsExact(KbPrime);

        return Ka.Concat(Kb).ToArray();
    }

    static byte[] AdjustParityBitsExact(byte[] key)
    {
        byte[] adjustedKey = new byte[key.Length];

        for (int i = 0; i < key.Length; i++)
        {
            byte currentByte = key[i];
            int numSetBits = CountSetBits(currentByte);

            // Om antalet '1'-bitar är jämnt, justera sista biten
            if (numSetBits % 2 == 0)
            {
                adjustedKey[i] = (byte)(currentByte ^ 1); // Ändra sista biten
            }
            else
            {
                adjustedKey[i] = currentByte; // Behåll byte som den är
            }
        }

        return adjustedKey;
    }

    // Räknar antalet '1'-bitar i en byte
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
}
