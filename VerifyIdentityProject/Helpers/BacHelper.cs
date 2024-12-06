using System.Security.Cryptography;
using System.Text;

namespace VerifyIdentityProject.Helpers;
public static class BacHelper
{
    public static byte[] DeriveKey(string passportNumber, string birthDate, string expiryDate)
    {
        string mrzInfo = passportNumber + birthDate + expiryDate;
        byte[] mrzBytes = Encoding.ASCII.GetBytes(mrzInfo);

        using (var sha1 = SHA1.Create())
        {
            byte[] hash = sha1.ComputeHash(mrzBytes);

            Console.WriteLine($"MRZ Info: {mrzInfo}");
            Console.WriteLine($"MRZ Bytes: {BitConverter.ToString(mrzBytes)}");
            Console.WriteLine($"SHA-1 Hash: {BitConverter.ToString(hash)}");
            Console.WriteLine($"SHA-1 Hash Length: {hash.Length}");

            return hash;
        }
    }

    public static (byte[] KEnc, byte[] KMac) GenerateBacKeys(string passportNumber, string birthDate, string expiryDate)
    {
        byte[] key = DeriveKey(passportNumber, birthDate, expiryDate);

        if (key.Length != 20)
        {
            throw new InvalidOperationException("SHA-1 hash is not the expected 20 bytes.");
        }

        byte[] KEnc = key.Take(16).ToArray();
        byte[] KMac = key.Skip(4).Take(16).ToArray();

        return (KEnc, KMac);
    }

}
