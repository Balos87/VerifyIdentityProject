using Android.Nfc.Tech;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureMessage3
    {
        private IsoDep _isoDep;
        private byte[] _ksEnc;
        private byte[] _ksMac;
        private byte[] _ssc;

        public SecureMessage3(byte[] ksEnc, byte[] ksMac, IsoDep isoDep)
        {
            _ksEnc = ksEnc;
            _ksMac = ksMac;
            _isoDep = isoDep;
            _ssc = new byte[16]; // PACE: 16 bytes av nollor
        }

        public byte[] SelectDG1()
        {
            Console.WriteLine("[DOTNET] Initial SSC: " + BitConverter.ToString(_ssc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsEnc: " + BitConverter.ToString(_ksEnc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsMac: " + BitConverter.ToString(_ksMac).Replace("-", " "));

            // Öka SSC före varje kommando
            IncrementSSC();
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            // Original command data för DG1
            byte[] commandData = new byte[] { 0x01, 0x01 };

            // 1. Padda data för kryptering
            byte[] paddedData = PadData(commandData);
            Console.WriteLine("[DOTNET] Padded data: " + BitConverter.ToString(paddedData).Replace("-", " "));

            // 2. Kryptera data med AES-CBC
            byte[] encryptedData = EncryptData(paddedData);
            Console.WriteLine("[DOTNET] Encrypted data: " + BitConverter.ToString(encryptedData).Replace("-", " "));

            // 3. Bygg DO'87'
            byte[] do87 = BuildDO87(encryptedData);
            Console.WriteLine("[DOTNET] DO'87': " + BitConverter.ToString(do87).Replace("-", " "));

            // 4. Bygg data för MAC-beräkning
            byte[] paddedHeader = new byte[] { 0x0C, 0xA4, 0x02, 0x0C, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] dataToMac = ConcatenateArrays(paddedHeader, do87);

            // Padda hela M-strängen
            dataToMac = PadData(dataToMac);
            Console.WriteLine("[DOTNET] Padded data to MAC: " + BitConverter.ToString(dataToMac).Replace("-", " "));

            // 5. Beräkna MAC
            byte[] mac = CalculateMAC(dataToMac);
            Console.WriteLine("[DOTNET] Calculated MAC: " + BitConverter.ToString(mac).Replace("-", " "));

            // 6. Bygg DO'8E'
            byte[] do8E = BuildDO8E(mac);
            Console.WriteLine("[DOTNET] DO'8E': " + BitConverter.ToString(do8E).Replace("-", " "));

            // 7. Bygg final protected APDU
            byte[] protectedApdu = BuildProtectedAPDU(paddedHeader, do87, do8E);

            Console.WriteLine("[DOTNET] Protected APDU: " + BitConverter.ToString(protectedApdu).Replace("-", " "));

            var reponse = _isoDep.Transceive(protectedApdu);
            Console.WriteLine("[DOTNET] reponse: " + BitConverter.ToString(reponse).Replace("-", " "));

            return reponse;
        }

        private byte[] PadData(byte[] data)
        {
            int paddingLength = 16 - (data.Length % 16);
            byte[] paddedData = new byte[data.Length + paddingLength];
            Buffer.BlockCopy(data, 0, paddedData, 0, data.Length);
            paddedData[data.Length] = 0x80;
            return paddedData;
        }

        private byte[] EncryptData(byte[] paddedData)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = _ksEnc;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                // För PACE: IV är krypterad SSC
                byte[] iv = CalculateIV();
                Console.WriteLine("[DOTNET] Calculated IV: " + BitConverter.ToString(iv).Replace("-", " "));
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(paddedData, 0, paddedData.Length);
                }
            }
        }

        private byte[] CalculateIV()
        {
            using (Aes aes = Aes.Create())
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

        private byte[] CalculateMAC(byte[] data)
        {
            // För PACE: Använd AES-CMAC
            // Först konkatenera SSC
            byte[] macInput = ConcatenateArrays(_ssc, data);
            Console.WriteLine("[DOTNET] Full MAC input with SSC: " + BitConverter.ToString(macInput).Replace("-", " "));

            var cipher = new AesEngine();
            var mac = new CMac(cipher, 128);
            mac.Init(new KeyParameter(_ksMac));
            mac.BlockUpdate(macInput, 0, macInput.Length);

            byte[] fullMac = new byte[16];
            mac.DoFinal(fullMac, 0);

            return fullMac.Take(8).ToArray();
        }

        private byte[] BuildProtectedAPDU(byte[] header, byte[] do87, byte[] do8E)
        {
            // Använd original header här (utan padding)
            byte[] protectedApdu = new byte[] { 0x0C, 0xA4, 0x02, 0x0C } // Notera: P2 = 0x0C här
                .Concat(new byte[] { (byte)(do87.Length + do8E.Length) })
                .Concat(do87)
                .Concat(do8E)
                .Concat(new byte[] { 0x00 })
                .ToArray();

            return protectedApdu;
        }

        private byte[] BuildDO87(byte[] encryptedData)
        {
            return new byte[] { 0x87 }
                .Concat(new byte[] { (byte)(encryptedData.Length + 1) })
                .Concat(new byte[] { 0x01 })
                .Concat(encryptedData)
                .ToArray();
        }

        private byte[] BuildDO8E(byte[] mac)
        {
            return new byte[] { 0x8E, 0x08 }
                .Concat(mac)
                .ToArray();
        }

        private void IncrementSSC()
        {
            for (int i = _ssc.Length - 1; i >= 0; i--)
            {
                if (++_ssc[i] != 0)
                    break;
            }
        }

        private byte[] ConcatenateArrays(params byte[][] arrays)
        {
            return arrays.SelectMany(x => x).ToArray();
        }
    }
}
