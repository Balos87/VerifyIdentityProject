using Android.Nfc.Tech;
using Microsoft.Maui.Controls;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VerifyIdentityProject.Helpers;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureMessage2
    {
        private IsoDep _isoDep;
        private byte[] _ksEnc;
        private byte[] _ksMac;   
        private byte[] _ssc;     

        public SecureMessage2(byte[] ksEnc, byte[] ksMac, IsoDep isoDep)
        {
            _ksEnc = ksEnc;
            _ksMac = ksMac;
            _isoDep = isoDep;
            _ssc = new byte[16];
        }

        public bool PerformSecureMessage()
        {
            Console.WriteLine("-------------------------------------Secure Messaging started..");
            try
            {
                byte[] protectedApduDG1 = SelectFileDG1();
                Console.WriteLine($"Sending protectedApduDG1: {BitConverter.ToString(protectedApduDG1)}");

                byte[] response = _isoDep.Transceive(protectedApduDG1);
                Console.WriteLine($"response protectedApduDG1: {BitConverter.ToString(response)}");

                if (!IsSuccessfulResponse(response))
                {
                    Console.WriteLine($"Failed to select passport application. Response:{BitConverter.ToString(response)}");
                    return false;
                }
                Console.WriteLine($"Application selected. Response:{BitConverter.ToString(response)}");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false;
            }
        }

        private void IncrementSsc()
        {
            for (int i = _ssc.Length - 1; i >= 0; i--)
            {
                if (++_ssc[i] != 0)
                    break;
            }
        }

        private byte[] CalculateIV()
        {
            // Använd AES för att kryptera SSC för att få IV
            using var aes = Aes.Create();
            aes.Key = _ksEnc;
            aes.Mode = CipherMode.ECB;  // Vi krypterar bara ett block
            aes.Padding = PaddingMode.None;

            var encryptor = aes.CreateEncryptor();
            var iv = new byte[16];
            encryptor.TransformBlock(_ssc, 0, _ssc.Length, iv, 0);
            return iv;
        }
        //------------------------------------Padded data gives total 16byte data with padding. ✔️✅
        private byte[] PadData(byte[] data)
        {
            int blockSize = 16;
            int paddedLength = ((data.Length + blockSize) / blockSize) * blockSize;
            byte[] paddedData = new byte[paddedLength];
            Array.Copy(data, paddedData, data.Length);
            paddedData[data.Length] = 0x80; // Längdbyte
            return paddedData;
        }

        private byte[] EncryptWithKEncAes(byte[] data)
        {
            Console.WriteLine($"-IV for encryptData-: {BitConverter.ToString(CalculateIV())}");
            Console.WriteLine($"-SSC used for encryptData-: {BitConverter.ToString(_ssc)}");
            Console.WriteLine($"-ksEnc used for encryptData-: {BitConverter.ToString(_ksEnc)}");
            Console.WriteLine($"-ksEnc length-: {_ksEnc.Length}");
            //nödvändigt?
           // paddedData = ApplyPadding(paddedData);

            using var aes = Aes.Create();
            aes.Key = _ksEnc;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.IV = CalculateIV();


            int blockSize = 16;
            int paddedLength = (data.Length + blockSize - 1) / blockSize * blockSize;
            byte[] paddedData = new byte[paddedLength];
            Array.Copy(data, paddedData, data.Length);

            var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(paddedData, 0, paddedData.Length);
        }

        private byte[] CalculateMac(byte[] data)
        {
            Console.WriteLine($"-ksMac using for calculateMac-: {BitConverter.ToString(_ksMac)}");
            Console.WriteLine($"-ksMac length-: {_ksMac.Length}");

            var cmac = new CMac(new AesEngine(),128);
            cmac.Init(new KeyParameter(_ksMac));

            // Padda till nästa 16-byte block
            var paddedMacInput = PadData(data);
  
            Console.WriteLine($"-dataForMac after padding-: {BitConverter.ToString(paddedMacInput)}");
            Console.WriteLine($"-dataForMac length-: {paddedMacInput.Length}");

            byte[] fullMac = new byte[16];
            cmac.BlockUpdate(paddedMacInput, 0, paddedMacInput.Length);
            cmac.DoFinal(fullMac, 0);

            return fullMac.Take(8).ToArray();
        }

        public byte[] SelectFileDG1()
        {
            // Original command: 00 A4 02 0C 02 0101 ------------- should it be 8 bytes with padding? or 16 bytes with padding or just the header❓❔ , 0x80, 0x00,0x00,0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            byte[] commandHeader = new byte[] { 0x0C, 0xA4, 0x02, 0x0C };
            Console.WriteLine($"-cmdHeader-: {BitConverter.ToString(commandHeader)}");

            byte[] fileId = new byte[] { 0x01, 0x01 };
            Console.WriteLine($"-fileId-: {BitConverter.ToString(fileId)}");

            // 1. Increment SSC ✔️✅
            IncrementSsc();
            Console.WriteLine($"-Incremented ssc-: {BitConverter.ToString(_ssc)}");

            // 2. Pad and encrypt data checked ✔️✅
            byte[] paddedData = PadData(fileId);
            Console.WriteLine($"-padded fileId-: {BitConverter.ToString(paddedData)}");


            byte[] encryptedData = EncryptWithKEncAes(paddedData);
            Console.WriteLine($"-encryptedData-: {BitConverter.ToString(encryptedData)}");

            // 3. Build DO'87' ----------------second number presents the remaining length of the data object. should be 0x11 ✔️✅
            var DO87 = BuildDO87(encryptedData);
            Console.WriteLine($"-DO87-: {BitConverter.ToString(DO87)}");

            // 4. Build data for MAC calculation
            byte[] M = commandHeader.Concat(DO87).ToArray();
            Console.WriteLine($"-M-: {BitConverter.ToString(M)}");

            Console.WriteLine($"Incremented SSC: {BitConverter.ToString(_ssc)}");

            var dataForMac = _ssc.Concat(M).ToArray();
            Console.WriteLine($"dataForMac: {BitConverter.ToString(dataForMac)}");

            // 5. Calculate MAC
            byte[] mac = CalculateMac(dataForMac);
            Console.WriteLine($"-CalculateMac-: {BitConverter.ToString(mac)}");

            // 6. Build DO'8E'
            var do8E = new List<byte> { 0x8E, 0x08 };
            do8E.AddRange(mac);

            // 7. Build protected APDU
            var protectedApdu = new List<byte>();
            protectedApdu.AddRange(new byte[] { 0x0C, 0xA4, 0x02, 0x0C });
            protectedApdu.Add((byte)(DO87.Length + do8E.Count)); // Lc
            protectedApdu.AddRange(DO87);
            protectedApdu.AddRange(do8E);
            protectedApdu.Add(0x00); // Le

            return protectedApdu.ToArray();
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

        private byte[] BuildDO87(byte[] encryptedData)
        {
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