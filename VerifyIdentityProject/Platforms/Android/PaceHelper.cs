using System;
using System.Security.Cryptography;
using System.Text;

public class PaceHelper
{
    // Metod för att dekryptera noncen (z)
    public static byte[] DecryptNonce(byte[] encryptedNonce, string mrz)
    {
        encryptedNonce = new byte[] { 0x95, 0xA3, 0xA0, 0x16, 0x52, 0x2E, 0xE9, 0x8D, 0x01, 0xE7, 0x6C, 0xB6, 0xB9, 0x8B, 0x42, 0xC3 };
        string mrs = "T22000129364081251010318";
        // Härled nyckeln Kn från MRZ
        byte[] Kn = DeriveKeyFromMRZ(mrs);

        // Dekryptera noncen (z) med AES-256 i CBC-läge
        byte[] decryptedNonce = DecryptAesCbc(encryptedNonce, Kn);

        return decryptedNonce;
    }

    // Härled nyckeln Kn från MRZ
    private static byte[] DeriveKeyFromMRZ(string mrz)
    {
        // Beräkna K med SHA-256
        byte[] K = ComputeSha256Hash(Encoding.ASCII.GetBytes(mrz));

        // Härled Kn med KDF (använd K som input och härled med index 3)
        byte[] Kn = Kdf(K, 3);

        return Kn;
    }

    // Beräkna SHA-256 hash
    private static byte[] ComputeSha256Hash(byte[] input)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            return sha256.ComputeHash(input);
        }
    }

    // KDF (Key Derivation Function)
    private static byte[] Kdf(byte[] input, int index)
    {
        byte[] counter = BitConverter.GetBytes(index);
        byte[] inputWithCounter = new byte[input.Length + counter.Length];
        Buffer.BlockCopy(input, 0, inputWithCounter, 0, input.Length);
        Buffer.BlockCopy(counter, 0, inputWithCounter, input.Length, counter.Length);

        return ComputeSha256Hash(inputWithCounter);
    }

    // Dekryptera med AES-256 i CBC-läge och ISO/IEC 9797-1 padding
    private static byte[] DecryptAesCbc(byte[] cipherText, byte[] key)
    {
        // IV är alltid 0x00 för PACE
        byte[] iv = new byte[16];

        // Logga nyckellängden och IV
        Console.WriteLine("Nyckellängd: " + key.Length);
        Console.WriteLine("IV: " + BitConverter.ToString(iv));

        // Kontrollera ciphertextens längd
        if (cipherText.Length % 16 != 0)
        {
            throw new Exception("Ciphertext längd är inte ett multipel av 16 bytes!");
        }

        // Skapa AES-dekrypterare
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None; // Inaktivera padding i AES

            // Dekryptera
            using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                byte[] plainText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);

                // Ta bort ISO/IEC 9797-1 padding manuellt
                

                return plainText;
            }
        }
    }

    // Ta bort ISO/IEC 9797-1 padding manuellt
    private static byte[] RemoveIsoPadding(byte[] data)
    {
        int paddingLength = data[data.Length - 1];
        if (paddingLength > data.Length || paddingLength > 255)
        {
            throw new Exception("Ogiltig padding!");
        }

        byte[] result = new byte[data.Length - paddingLength];
        Buffer.BlockCopy(data, 0, result, 0, result.Length);
        return result;
    }
}
