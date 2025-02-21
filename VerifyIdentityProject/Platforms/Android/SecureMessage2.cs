using Android.Nfc.Tech;
using Microsoft.Maui.Controls;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VerifyIdentityProject.Helpers;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureMessage2
    {
        private readonly IsoDep _isoDep;
        private byte[] _ksEnc;
        private byte[] _ksMac;
        private byte[] _ssc;
        public SecureMessage2(byte[] ksEnc, byte[] ksMac, IsoDep isoDep)
        {
            _ksEnc = ksEnc;
            _ksMac = ksMac;
            _isoDep = isoDep;
        }

        public bool PerformSecureMessage()
        {
            Console.WriteLine("-------------------------------------Secure Messaging started..");
            try
            {
                InitializeSSC();
                Console.WriteLine($"KSEnc: {BitConverter.ToString(_ksEnc)}");
                Console.WriteLine($"KSMac: {BitConverter.ToString(_ksMac)}");
                // Original SELECT command
                byte[] selectApdu = new byte[]
                {
                    0x0C,
                    0xA4, 0x04, 0x0C, 0x07,
                    0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01, 0x00,
                };

                // Protect command
                byte[] protectedApdu = ProtectAPDU(selectApdu);

                Console.WriteLine($"Protected selectApdu: {BitConverter.ToString(protectedApdu)}");
                byte[] response = _isoDep.Transceive(protectedApdu);

                // Unprotect response
                byte[] unprotectedResponse = UnprotectAPDU(response);

                if (!IsSuccessfulResponse(unprotectedResponse))
                {
                    Console.WriteLine($"Failed to select passport application. Response:{BitConverter.ToString(unprotectedResponse)}");
                    return false;
                }

                Console.WriteLine($"Application selected. Response:{BitConverter.ToString(unprotectedResponse)}");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false;
            }


            var secrets = GetSecrets.FetchSecrets();
            var mrzData = secrets?.MRZ_NUMBERS ?? string.Empty;
            return true;
        }

        private byte[] ProtectAPDU(byte[] apdu)
        {
            IncrementSSC();
            byte[] iv = CalculateIV();

            // Get command data without Le
            byte[] commandData = null;
            if (apdu.Length > 5)
            {
                int dataLength = apdu[4];  // Lc
                commandData = new byte[dataLength];
                Array.Copy(apdu, 5, commandData, 0, dataLength);
            }

            // Pad and encrypt data
            byte[] paddedData = PadData(commandData);
            byte[] encryptedData = EncryptData(paddedData, iv);

            // Build DO'87'
            byte[] do87 = BuildDO87(encryptedData);

            // Build DO'97' with Le
            byte[] do97 = BuildDO97(apdu[apdu.Length - 1]);  // Använd sista byten som Le

            // Build header
            byte[] header = new byte[] { apdu[0], apdu[1], apdu[2], apdu[3] };

            // Calculate MAC
            byte[] mac = CalculateMAC(header, do87, do97);

            // Build DO'8E'
            byte[] do8E = BuildDO8E(mac);

            // Combine all
            return CombineAll(apdu[0], apdu[1], do87, do97, do8E);
        }

        private void InitializeSSC()
        {
            _ssc = new byte[16]; // 16 bytes av nollor för AES
            Console.WriteLine($"SSC initialized: {BitConverter.ToString(_ssc)}");
        }

        private void IncrementSSC()
        {
            for (int i = _ssc.Length - 1; i >= 0; i--)
            {
                if (++_ssc[i] != 0)
                    break;
            }
        }
        private static bool IsSuccessfulResponse(byte[] response)
        {
            return response.Length >= 2 && response[^2] == 0x90 && response[^1] == 0x00;
        }

        private byte[] CalculateIV()
        {
            using (var aes = Aes.Create())
            {
                aes.Key = _ksEnc;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(_ssc, 0, _ssc.Length);
                }
            }
        }

        private byte[] PadData(byte[] data)
        {
            if (data == null || data.Length == 0)
                return new byte[] { 0x01 };

            int paddingLength = 16 - (data.Length % 16);
            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, paddedData, data.Length);
            paddedData[data.Length] = 0x01;

            return paddedData;
        }

        private byte[] EncryptData(byte[] paddedData, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = _ksEnc;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(paddedData, 0, paddedData.Length);
                }
            }
        }

        private byte[] BuildDO87(byte[] encryptedData)
        {
            if (encryptedData == null || encryptedData.Length == 0)
                return Array.Empty<byte>();

            // Format: 87 L 01 || Encrypted Data
            byte[] do87 = new byte[encryptedData.Length + 3];
            do87[0] = 0x87;
            do87[1] = (byte)(encryptedData.Length + 1);
            do87[2] = 0x01;
            Array.Copy(encryptedData, 0, do87, 3, encryptedData.Length);

            return do87;
        }

        private byte[] BuildDO97(byte le)
        {
            // För SELECT kommando ska vi ha Le = 00
            return new byte[] { 0x97, 0x01, 0x00 };
        }

        private byte[] CalculateMAC(byte[] header, byte[] do87, byte[] do97)
        {
            using (var ms = new MemoryStream())
            {
                // SSC
                ms.Write(_ssc, 0, _ssc.Length);

                // Command Header
                ms.Write(header, 0, 4);

                // Beräkna total längd inklusive DO'8E' som kommer läggas till
                int totalLength = (do87?.Length ?? 0) + (do97?.Length ?? 0) + 10; // +10 för DO'8E'
                ms.WriteByte((byte)totalLength);

                // Data Objects i korrekt ordning
                if (do87.Length > 0) ms.Write(do87, 0, do87.Length);
                if (do97.Length > 0) ms.Write(do97, 0, do97.Length);

                byte[] input = ms.ToArray();
                Console.WriteLine($"MAC Input: {BitConverter.ToString(input)}");
                return CalculateCMAC(input, _ksMac);
            }
        }

        private byte[] CalculateCMAC(byte[] data, byte[] key)
        {
            var cmac = new CMac(new AesEngine());
            cmac.Init(new KeyParameter(key));
            byte[] result = new byte[cmac.GetMacSize()];
            cmac.BlockUpdate(data, 0, data.Length);
            cmac.DoFinal(result, 0);
            return result.Take(8).ToArray(); // Ta bara 8 bytes enligt specifikationen
        }

        private byte[] BuildDO8E(byte[] mac)
        {
            // Format: 8E 08 || MAC
            byte[] do8E = new byte[mac.Length + 2];
            do8E[0] = 0x8E;
            do8E[1] = 0x08;  // MAC length is always 8 bytes
            Array.Copy(mac, 0, do8E, 2, mac.Length);

            return do8E;
        }

        private byte[] CombineAll(byte cla, byte ins, byte[] do87, byte[] do97, byte[] do8E)
        {
            using (var ms = new MemoryStream())
            {
                // Header
                ms.WriteByte(0x0C);    // CLA
                ms.WriteByte(0xA4);    // INS
                ms.WriteByte(0x04);    // P1
                ms.WriteByte(0x0C);    // P2

                // Beräkna total längd för alla dataobjekt
                int totalLength = (do87?.Length ?? 0) + (do97?.Length ?? 0) + do8E.Length;
                ms.WriteByte((byte)totalLength);

                // Skriv dataobjekten i korrekt ordning enligt spec
                if (do87.Length > 0) ms.Write(do87, 0, do87.Length);
                if (do97.Length > 0) ms.Write(do97, 0, do97.Length);
                ms.Write(do8E, 0, do8E.Length);

                return ms.ToArray();
            }
        }

        private byte[] UnprotectAPDU(byte[] protectedResponse)
        {
            try
            {
                if (protectedResponse == null || protectedResponse.Length < 2)
                    throw new Exception("Invalid response length");

                // Extract status bytes
                byte[] statusBytes = new byte[] {
                protectedResponse[protectedResponse.Length - 2],
                protectedResponse[protectedResponse.Length - 1]
            };

                // If it's an error response, return directly
                if (statusBytes[0] != 0x90 || statusBytes[1] != 0x00)
                    return statusBytes;

                // Parse DO'87' (if present) and DO'8E'
                int offset = 0;
                byte[] decryptedData = null;
                byte[] responseMAC = null;

                while (offset < protectedResponse.Length - 2)
                {
                    byte tag = protectedResponse[offset++];
                    int length = protectedResponse[offset++];

                    switch (tag)
                    {
                        case 0x87:
                            // Skip 0x01 marker
                            offset++;
                            length--;

                            // Decrypt the data
                            byte[] encryptedData = new byte[length];
                            Array.Copy(protectedResponse, offset, encryptedData, 0, length);
                            decryptedData = DecryptResponse(encryptedData);
                            offset += length;
                            break;

                        case 0x8E:
                            responseMAC = new byte[length];
                            Array.Copy(protectedResponse, offset, responseMAC, 0, length);
                            offset += length;
                            break;
                    }
                }

                // Verify MAC
                if (!VerifyResponseMAC(protectedResponse, responseMAC))
                    throw new Exception("Response MAC verification failed");

                // Combine decrypted data with status bytes
                if (decryptedData != null)
                {
                    byte[] result = new byte[decryptedData.Length + 2];
                    Array.Copy(decryptedData, result, decryptedData.Length);
                    Array.Copy(statusBytes, 0, result, decryptedData.Length, 2);
                    return result;
                }

                return statusBytes;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error unprotecting APDU: {ex.Message}");
                throw;
            }
        }

        private byte[] DecryptResponse(byte[] encryptedData)
        {
            IncrementSSC();
            byte[] iv = CalculateIV();

            using (var aes = Aes.Create())
            {
                aes.Key = _ksEnc;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (var decryptor = aes.CreateDecryptor())
                {
                    byte[] decryptedData = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                    return UnpadData(decryptedData);
                }
            }
        }

        private byte[] UnpadData(byte[] paddedData)
        {
            int lastIndex = paddedData.Length - 1;
            while (lastIndex >= 0 && paddedData[lastIndex] == 0x00)
                lastIndex--;

            if (lastIndex < 0 || paddedData[lastIndex] != 0x01)
                throw new Exception("Invalid padding");

            byte[] unpaddedData = new byte[lastIndex];
            Array.Copy(paddedData, unpaddedData, lastIndex);
            return unpaddedData;
        }

        private bool VerifyResponseMAC(byte[] protectedResponse, byte[] responseMAC)
        {
            if (responseMAC == null || responseMAC.Length != 8)
                return false;

            // Calculate MAC over the response data (excluding MAC itself and status bytes)
            int macDataLength = protectedResponse.Length - 10; // Exclude MAC (8 bytes) and status bytes (2 bytes)
            byte[] macData = new byte[macDataLength];
            Array.Copy(protectedResponse, macData, macDataLength);

            // Calculate expected MAC
            byte[] expectedMAC = CalculateCMAC(macData, _ksMac);

            // Compare MACs
            return responseMAC.SequenceEqual(expectedMAC);
        }
    }

}