using System.Security.Cryptography;
using System.Text;

namespace VerifyIdentityProject.Helpers;
public static class BacHelper
{
    private static byte[] DeriveKSeed(string passportNumber, string birthDate, string expiryDate)
    {
        string mrzInfo = passportNumber + birthDate + expiryDate;
        byte[] mrzBytes = Encoding.ASCII.GetBytes(mrzInfo);

        using (var sha1 = SHA1.Create())
        {
            byte[] hash = sha1.ComputeHash(mrzBytes);
            return hash.Take(16).ToArray(); // Most significant 16 bytes
        }
    }

    public static (byte[] KEnc, byte[] KMac) GenerateBacKeys(string passportNumber, string birthDate, string expiryDate)
    {
        byte[] kSeed = DeriveKSeed(passportNumber, birthDate, expiryDate);

        byte[] kEnc = KDF(kSeed, 1); // KDF(KSeed, 1) for encryption key
        byte[] kMac = KDF(kSeed, 2); // KDF(KSeed, 2) for MAC key

        // Validate lengths
        //if (kEnc.Length != 16 || kMac.Length != 16)
        //{
        //    throw new InvalidOperationException("Invalid key length derived. Keys must be 16 bytes.");
        //}

        Console.WriteLine($"KEnc: {BitConverter.ToString(kEnc)}");
        Console.WriteLine($"KMac: {BitConverter.ToString(kMac)}");

        return (kEnc, kMac);
    }

    private static byte[] KDF(byte[] kSeed, int counter)
    {
        // Prepare input for SHA-1
        byte[] input = kSeed.Concat(new byte[] { 0x00, 0x00, 0x00, (byte)counter }).ToArray();

        using (var sha1 = SHA1.Create())
        {
            // Compute SHA-1 hash
            byte[] hash = sha1.ComputeHash(input);

            Console.WriteLine($"KDF Input Hash: {BitConverter.ToString(hash)}");

            // Extract key parts
            byte[] keydataA = hash.Take(8).ToArray(); // First 8 bytes
            byte[] keydataB = hash.Skip(8).Take(8).ToArray(); // Next 8 bytes

            // Optional: Adjust parity bits for DES compliance
            keydataA = AdjustParityBits(keydataA);
            keydataB = AdjustParityBits(keydataB);

            // Form the 3DES key (16 bytes: keydataA || keydataB)
            byte[] key = keydataA.Concat(keydataB).ToArray();

            // Validate the key length
            if (key.Length != 16)
            {
                throw new InvalidOperationException("Derived 3DES key must be 16 bytes.");
            }

            Console.WriteLine($"Derived Key: {BitConverter.ToString(key)}");
            return key;
        }
    }

    private static byte[] EnsureValid3DesKey(byte[] key)
    {
        if (key.Length != 16 && key.Length != 24)
            throw new ArgumentException("3DES keys must be 16 or 24 bytes long.");
        return key.Length == 16 ? key.Concat(key.Take(8)).ToArray() : key; // Ensure 24 bytes
    }

    // Adjust DES key parity bits
    private static byte[] AdjustParityBits(byte[] key)
    {
        // Validate key length (DES requires 8 bytes per block)
        if (key.Length != 8 && key.Length != 16)
        {
            throw new ArgumentException("Invalid key length. Key must be 8 or 16 bytes.");
        }

        Console.WriteLine($"Adjusting parity bits for key: {BitConverter.ToString(key)}");

        byte[] adjustedKey = new byte[key.Length];
        for (int i = 0; i < key.Length; i++)
        {
            int parity = 0;
            byte b = key[i];

            // Count the 1s in the first 7 bits
            for (int j = 0; j < 7; j++)
            {
                parity ^= (b >> j) & 1;
            }

            // Adjust the least significant bit to ensure odd parity
            adjustedKey[i] = (byte)((b & 0xFE) | (parity ^ 1));

            Console.WriteLine($"Original byte: {b:X2}, Adjusted byte: {adjustedKey[i]:X2}");
        }

        Console.WriteLine($"Adjusted key: {BitConverter.ToString(adjustedKey)}");
        return adjustedKey;
    }

    public static (byte[] KSEnc, byte[] KSMac) DeriveSessionKeys(byte[] KEnc, byte[] KMac, byte[] rndIFD, byte[] rndIC)
    {
        byte[] seed = rndIFD.Concat(rndIC).ToArray();

        Console.WriteLine($"Session Seed: {BitConverter.ToString(seed)}");

        byte[] KSEnc = DeriveKey(KEnc, seed, "ENC");
        byte[] KSMac = DeriveKey(KMac, seed, "MAC");

        Console.WriteLine($"Derived KSEnc: {BitConverter.ToString(KSEnc)}");
        Console.WriteLine($"Derived KSMac: {BitConverter.ToString(KSMac)}");

        return (KSEnc, KSMac);
    }

    private static byte[] DeriveKey(byte[] key, byte[] seed, string purpose)
    {
        using (var des = TripleDES.Create())
        {
            des.Key = key;
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;

            // Prepare input with padding
            byte[] input = seed.Concat(Encoding.UTF8.GetBytes(purpose)).ToArray();
            input = PadToBlockSize(input, 8); // Ensure input is a multiple of 8 bytes

            using (var encryptor = des.CreateEncryptor())
            {
                return encryptor.TransformFinalBlock(input, 0, input.Length);
            }
        }
    }

    private static byte[] PadToBlockSize(byte[] data, int blockSize)
    {
        int paddedLength = ((data.Length + blockSize - 1) / blockSize) * blockSize;
        byte[] paddedData = new byte[paddedLength];
        Array.Copy(data, paddedData, data.Length);
        return paddedData;
    }


}
