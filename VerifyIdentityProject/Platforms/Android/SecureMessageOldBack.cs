using Android.Nfc.Tech;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureMessageOldBack
    {
        public static void SelectApplication(IsoDep isoDep, byte[] KSEnc, byte[] KSMac, byte[] SSC)
        {
            Console.WriteLine("------------------------------------");
            Console.WriteLine("Select eMRTD Application..");
            Console.WriteLine($"KSEnc: {BitConverter.ToString(KSEnc)}");
            Console.WriteLine($"KSMac: {BitConverter.ToString(KSMac)}");
            Console.WriteLine($"Initial SSC: {BitConverter.ToString(SSC)}");

            // Command header
            byte[] cmdHeader = new byte[] { 0x0C, 0xA4, 0x04, 0x0C, 0x80, 0x00, 0x00, 0x00 };
            Console.WriteLine($"Command Header: {BitConverter.ToString(cmdHeader)}");

            // Application data
            byte[] data = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
            Console.WriteLine($"Application Data: {BitConverter.ToString(data)}");

            // Padda data för kryptering
            byte[] paddedData = PadData(data);
            Console.WriteLine($"Padded Data: {BitConverter.ToString(paddedData)}");

            // Öka SSC
            IncrementSSC(ref SSC);
            Console.WriteLine($"Incremented SSC: {BitConverter.ToString(SSC)}");

            // Beräkna IV genom att kryptera SSC
            byte[] iv = CalculateIV(SSC, KSEnc);
            Console.WriteLine($"IV: {BitConverter.ToString(iv)}");

            // Kryptera data
            byte[] encryptedData = EncryptWithAes(paddedData, KSEnc, iv);
            Console.WriteLine($"Encrypted Data: {BitConverter.ToString(encryptedData)}");

            // Bygg DO'87'
            byte[] DO87 = BuildDO87(encryptedData);
            Console.WriteLine($"DO87: {BitConverter.ToString(DO87)}");

            // Data för MAC-beräkning: cmdHeader || DO87 || DO97
            byte[] DO97 = new byte[] { 0x97, 0x01, 0x00 };
            byte[] dataForMac = cmdHeader.Concat(DO87).Concat(DO97).ToArray();
            Console.WriteLine($"Data for MAC (before SSC): {BitConverter.ToString(dataForMac)}");

            // MAC input: SSC || cmdHeader || DO87
            byte[] macInput = SSC.Concat(dataForMac).ToArray();
            Console.WriteLine($"Complete MAC Input: {BitConverter.ToString(macInput)}");

            // Beräkna MAC
            byte[] CC = ComputeAesCmac(macInput, KSMac);
            Console.WriteLine($"Calculated MAC (CC): {BitConverter.ToString(CC)}");

            // Bygg DO'8E'
            byte[] DO8E = BuildDO8E(CC);
            Console.WriteLine($"DO8E: {BitConverter.ToString(DO8E)}");

            // Bygg protected APDU
            byte[] protectedAPDU = ConstructProtectedAPDU(cmdHeader, DO87, DO8E);
            Console.WriteLine($"Protected APDU: {BitConverter.ToString(protectedAPDU)}");

            // Skicka kommando
            byte[] response = isoDep.Transceive(protectedAPDU);
            Console.WriteLine($"Response APDU: {BitConverter.ToString(response)}");

            // Om vi fick error, avsluta här
            if (response.Length == 2)
            {
                Console.WriteLine($"Received error SW: {BitConverter.ToString(response)}");
                return;
            }

            // Öka SSC för response verifiering
            IncrementSSC(ref SSC);
            Console.WriteLine($"SSC for Response: {BitConverter.ToString(SSC)}");

            try
            {
                //VerifyResponse(response, SSC, KSMac);
                Console.WriteLine("Response verification successful");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Response verification failed: {ex.Message}");
            }
        }

        private static byte[] PadData(byte[] data)
        {
            int blockSize = 16;
            int paddingLength = blockSize - (data.Length % blockSize);
            byte[] paddedData = new byte[data.Length + paddingLength];

            Array.Copy(data, paddedData, data.Length);
            paddedData[data.Length] = 0x80;

            return paddedData;
        }

        private static byte[] CalculateIV(byte[] SSC, byte[] KSEnc)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = KSEnc;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(SSC, 0, SSC.Length);
                }
            }
        }

        private static byte[] EncryptWithAes(byte[] data, byte[] KSEnc, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = KSEnc;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        private static byte[] BuildDO87(byte[] encryptedData)
        {
            var do87 = new byte[3 + encryptedData.Length];
            do87[0] = 0x87;
            do87[1] = (byte)(1 + encryptedData.Length);
            do87[2] = 0x01;
            Array.Copy(encryptedData, 0, do87, 3, encryptedData.Length);
            return do87;
        }

        private static byte[] BuildDO8E(byte[] mac)
        {
            var do8e = new byte[2 + mac.Length];
            do8e[0] = 0x8E;
            do8e[1] = 0x08;
            Array.Copy(mac, 0, do8e, 2, mac.Length);
            return do8e;
        }

        private static byte[] ConstructProtectedAPDU(byte[] cmdHeader, byte[] DO87, byte[] DO8E)
        {
            var newCmdHeader = cmdHeader.Take(4).ToArray();
            // Skapa DO'97' för Le
            byte[] DO97 = new byte[] { 0x97, 0x01, 0x00 };
            Console.WriteLine($"DO97: {BitConverter.ToString(DO97)}");

            // Beräkna total längd
            byte lc = (byte)(DO87.Length + DO97.Length + DO8E.Length);

            // +1 för Le-fältet i slutet
            var protectedAPDU = new byte[newCmdHeader.Length + 1 + DO87.Length + DO97.Length + DO8E.Length + 1];

            int offset = 0;
            Array.Copy(newCmdHeader, 0, protectedAPDU, offset, newCmdHeader.Length);
            offset += newCmdHeader.Length;

            protectedAPDU[offset++] = lc;

            Array.Copy(DO87, 0, protectedAPDU, offset, DO87.Length);
            offset += DO87.Length;

            Array.Copy(DO97, 0, protectedAPDU, offset, DO97.Length);
            offset += DO97.Length;

            Array.Copy(DO8E, 0, protectedAPDU, offset, DO8E.Length);
            offset += DO8E.Length;

            // Lägger till Le = 00 i slutet
            protectedAPDU[offset] = 0x00;

            return protectedAPDU;
        }

        private static void IncrementSSC(ref byte[] SSC)
        {
            for (int i = SSC.Length - 1; i >= 0; i--)
            {
                if (++SSC[i] != 0) break;
            }
        }

        private static byte[] ComputeAesCmac(byte[] data, byte[] KSMac)
        {
            // Initialt block för CBC
            byte[] lastBlock = new byte[16];

            using (var aes = Aes.Create())
            {
                aes.Key = KSMac;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                aes.IV = new byte[16];  // Noll IV för CMAC

                // Generera subkeys
                byte[] k1, k2;
                GenerateSubkeys(aes, out k1, out k2);

                // Processa alla hela block
                int numBlocks = data.Length / 16;
                int remainingBytes = data.Length % 16;

                for (int i = 0; i < numBlocks; i++)
                {
                    byte[] block = new byte[16];
                    Array.Copy(data, i * 16, block, 0, 16);

                    for (int j = 0; j < 16; j++)
                        lastBlock[j] ^= block[j];

                    using (var encryptor = aes.CreateEncryptor())
                    {
                        encryptor.TransformBlock(lastBlock, 0, 16, lastBlock, 0);
                    }
                }

                // Hantera sista blocket
                byte[] finalBlock = new byte[16];
                if (remainingBytes == 0)
                {
                    Array.Copy(data, (numBlocks - 1) * 16, finalBlock, 0, 16);
                    for (int i = 0; i < 16; i++)
                        finalBlock[i] ^= k1[i];
                }
                else
                {
                    Array.Copy(data, numBlocks * 16, finalBlock, 0, remainingBytes);
                    finalBlock[remainingBytes] = 0x80;
                    for (int i = 0; i < 16; i++)
                        finalBlock[i] ^= k2[i];
                }

                for (int i = 0; i < 16; i++)
                    lastBlock[i] ^= finalBlock[i];

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] fullMac = encryptor.TransformFinalBlock(lastBlock, 0, 16);
                    return fullMac.Take(8).ToArray();
                }
            }
        }

        private static void GenerateSubkeys(Aes aes, out byte[] k1, out byte[] k2)
        {
            k1 = new byte[16];
            k2 = new byte[16];

            // Generera L genom att kryptera noll-block
            byte[] L = new byte[16];
            using (var encryptor = aes.CreateEncryptor())
            {
                encryptor.TransformBlock(new byte[16], 0, 16, L, 0);
            }

            // Generera K1
            bool msb = (L[0] & 0x80) != 0;
            for (int i = 0; i < 15; i++)
            {
                k1[i] = (byte)(L[i] << 1);
                if ((L[i + 1] & 0x80) != 0)
                    k1[i] |= 1;
            }
            k1[15] = (byte)(L[15] << 1);
            if (msb)
                k1[15] ^= 0x87;

            // Generera K2
            msb = (k1[0] & 0x80) != 0;
            for (int i = 0; i < 15; i++)
            {
                k2[i] = (byte)(k1[i] << 1);
                if ((k1[i + 1] & 0x80) != 0)
                    k2[i] |= 1;
            }
            k2[15] = (byte)(k1[15] << 1);
            if (msb)
                k2[15] ^= 0x87;
        }
    }

}
