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

        // Use the first 16 bytes of the hash as Kseed
        byte[] kseed = new byte[16];
        Array.Copy(sha1Hash, kseed, 16);

        // Generate KEnc and KMac
        byte[] kenc = DeriveKey(kseed, 1); // Counter = 1
        byte[] kmac = DeriveKey(kseed, 2); // Counter = 2

        // Print results
        Console.WriteLine("KEnc: " + BitConverter.ToString(kenc).Replace("-", "").ToLower());
        Console.WriteLine("KMac: " + BitConverter.ToString(kmac).Replace("-", "").ToLower());



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
