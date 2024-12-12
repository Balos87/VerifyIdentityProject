using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    public static class KeyDerivationHelper
    {
        public static byte[] DeriveKey(string passportNumber, string birthDate, string expiryDate)
        {
            string mrzLine2 = "94279521<5SWE9004089M2303060199004082898<<44";
            passportNumber = mrzLine2.Substring(0, 9); ; // Example passport number
            birthDate = mrzLine2.Substring(12, 6);  // Example birth date (YYMMDD)
            expiryDate = mrzLine2.Substring(20, 6); // Example expiry date (YYMMDD)
            string mrzInfo = passportNumber + birthDate + expiryDate;
            byte[] mrzBytes = Encoding.ASCII.GetBytes(mrzInfo);

            using (var sha1 = SHA1.Create())
            {
                byte[] hash = sha1.ComputeHash(mrzBytes);

                System.Diagnostics.Debug.WriteLine($"MRZ Info: {mrzInfo}");
                System.Diagnostics.Debug.WriteLine($"MRZ Bytes: {BitConverter.ToString(mrzBytes)}");
                System.Diagnostics.Debug.WriteLine($"SHA-1 Hash: {BitConverter.ToString(hash)}");
                System.Diagnostics.Debug.WriteLine($"SHA-1 Hash Length: {hash.Length}");

                Console.WriteLine($"MRZ Info: {mrzInfo}");
                Console.WriteLine($"MRZ Bytes: {BitConverter.ToString(mrzBytes)}");
                Console.WriteLine($"SHA-1 Hash: {BitConverter.ToString(hash)}");
                Console.WriteLine($"SHA-1 Hash Length: {hash.Length}");

                if (hash.Length != 20)
                {
                    throw new InvalidOperationException("SHA-1 hash is not the expected 20 bytes.");
                }

                return hash;
            }
        }

    }
}

