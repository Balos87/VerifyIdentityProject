using System;
using System.Numerics;
using System.Security.Cryptography;

namespace VerifyIdentityProject.Platforms.Android
{

    // Klass för generering av ephemeral keys
    public class EphemeralKeyGenerator
    {
        private const int KEY_SIZE_BYTES = 48; // 384 bits för BrainpoolP384r1

        public static byte[] GeneratePrivateKey()
        {
            // Hämta ordningen som BigInteger
            BigInteger order = EcdhMapping.ToBigInteger(EcdhMapping.Order);

            // Skapa RNG
            using (var rng = RandomNumberGenerator.Create())
            {
                // Generera random bytes
                byte[] randomBytes = new byte[KEY_SIZE_BYTES];
                rng.GetBytes(randomBytes);

                // Konvertera till BigInteger och ta modulo order
                BigInteger privateKey = EcdhMapping.ToBigInteger(randomBytes);
                privateKey = privateKey % (order - 1) + 1;  // Säkerställer att resultatet är mellan 1 och order-1

                // Konvertera tillbaka till byte array
                byte[] result = privateKey.ToByteArray();

                // Säkerställ rätt längd
                if (result.Length < KEY_SIZE_BYTES)
                {
                    byte[] padded = new byte[KEY_SIZE_BYTES];
                    Array.Copy(result, 0, padded, KEY_SIZE_BYTES - result.Length, result.Length);
                    result = padded;
                }
                else if (result.Length > KEY_SIZE_BYTES)
                {
                    byte[] truncated = new byte[KEY_SIZE_BYTES];
                    Array.Copy(result, result.Length - KEY_SIZE_BYTES, truncated, 0, KEY_SIZE_BYTES);
                    result = truncated;
                }

                Console.WriteLine($"Generated private key ({KEY_SIZE_BYTES} bytes):");
                Console.WriteLine($"HEX: {BitConverter.ToString(result)}");
                return result;
            }
        }

        //Bara testar funktionen ovan. Kör denna metod för att testa.
        public static void TestKeyGeneration()
        {
            try
            {
                Console.WriteLine("Testing ephemeral key generation:");
                Console.WriteLine("=================================");

                byte[] key = GeneratePrivateKey();

                // Formatera output i 4-byte grupper för läsbarhet
                Console.WriteLine("\nFormatted output (4-byte groups):");
                for (int i = 0; i < key.Length; i += 4)
                {
                    int remainingBytes = Math.Min(4, key.Length - i);
                    byte[] group = new byte[remainingBytes];
                    Array.Copy(key, i, group, 0, remainingBytes);
                    Console.Write(BitConverter.ToString(group).Replace("-", " ") + " ");
                }
                Console.WriteLine("\n=================================");

                // Visa valideringsdetaljer
                BigInteger keyValue = EcdhMapping.ToBigInteger(key);
                BigInteger order = EcdhMapping.ToBigInteger(EcdhMapping.Order);
                Console.WriteLine($"\nValidation details:");
                Console.WriteLine($"Key < Order: {keyValue < order}");
                Console.WriteLine($"Key > 1: {keyValue > BigInteger.One}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Test failed: {ex.Message}");
            }
        }
    }
}
