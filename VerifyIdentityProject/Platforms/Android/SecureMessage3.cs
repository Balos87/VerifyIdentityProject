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
        private byte[] ssc;


        public SecureMessage3(byte[] ksEnc, byte[] ksMac, IsoDep isoDep)
        {
            _ksEnc = ksEnc;
            _ksMac = ksMac;
            _isoDep = isoDep;
            ssc = new byte[16];

        }
        public byte[] SelectApplication()
        {
            //var ssc = new byte[16]; // PACE: 16 bytes av nollor
            Console.WriteLine("------------------------------------------------------------Select application with secure message started...");
            Console.WriteLine("[DOTNET] Initial SSC: " + BitConverter.ToString(ssc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsEnc: " + BitConverter.ToString(_ksEnc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsMac: " + BitConverter.ToString(_ksMac).Replace("-", " "));

            // Öka SSC före varje kommando
            IncrementSSC(ref ssc);
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(ssc).Replace("-", " "));

            // Original command data för select application
            byte[] commandData = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

            // 1. Padda data för kryptering
            byte[] paddedData = PadData(commandData);
            Console.WriteLine("[DOTNET] Padded data: " + BitConverter.ToString(paddedData).Replace("-", " "));

            // 2. Kryptera data med AES-CBC
            byte[] encryptedData = EncryptData(paddedData, ssc);
            Console.WriteLine("[DOTNET] Encrypted data: " + BitConverter.ToString(encryptedData).Replace("-", " "));

            // 3. Bygg DO'87'
            byte[] do87 = BuildDO87(encryptedData);
            Console.WriteLine("[DOTNET] DO'87': " + BitConverter.ToString(do87).Replace("-", " "));

            // 4. Bygg data för MAC-beräkning
            byte[] paddedHeader = new byte[] { 0x0C, 0xA4, 0x04, 0x0C, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] dataToMac = ConcatenateArrays(paddedHeader, do87);
            Console.WriteLine("[DOTNET] cmdHeader+DO87: " + BitConverter.ToString(dataToMac).Replace("-", " "));


            // Padda hela M-strängen
            dataToMac = PadData(dataToMac);
            Console.WriteLine("[DOTNET] Padded data to MAC: " + BitConverter.ToString(dataToMac).Replace("-", " "));

            // 5. Beräkna MAC
            byte[] mac = CalculateMAC(dataToMac, ssc);
            Console.WriteLine("[DOTNET] Calculated MAC: " + BitConverter.ToString(mac).Replace("-", " "));

            // 6. Bygg DO'8E'
            byte[] do8E = BuildDO8E(mac);
            Console.WriteLine("[DOTNET] DO'8E': " + BitConverter.ToString(do8E).Replace("-", " "));

            // 7. Bygg final protected APDU
            byte[] protectedApdu = BuildProtectedAPDU(paddedHeader, do87, do8E);
            Console.WriteLine("[DOTNET] Protected APDU: " + BitConverter.ToString(protectedApdu).Replace("-", " "));

            var response = _isoDep.Transceive(protectedApdu);
            Console.WriteLine("[DOTNET] reponse: " + BitConverter.ToString(response).Replace("-", " "));


            // 8.Öka SSC för response verifiering
            IncrementSSC(ref ssc);
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(ssc).Replace("-", " "));

            try
            {
                VerifyResponse(response, ssc, _ksMac);
                Console.WriteLine("Response verification successful");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Response verification failed: {ex.Message}");
            }
            return response;
        }
        public byte[] SelectDG1()
        {
            Console.WriteLine("------------------------------------------------------------Select DG1 with secure message started...");
            //var ssc = new byte[16]; // PACE: 16 bytes av nollor
            Console.WriteLine("[DOTNET] Initial SSC: " + BitConverter.ToString(ssc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsEnc: " + BitConverter.ToString(_ksEnc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsMac: " + BitConverter.ToString(_ksMac).Replace("-", " "));

            // Öka SSC före varje kommando
            IncrementSSC(ref ssc);
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(ssc).Replace("-", " "));

            // Original command data för DG1
            byte[] commandData = new byte[] { 0x01, 0x01 };

            // 1. Padda data för kryptering
            byte[] paddedData = PadData(commandData);
            Console.WriteLine("[DOTNET] Padded data: " + BitConverter.ToString(paddedData).Replace("-", " "));

            // 2. Kryptera data med AES-CBC
            byte[] encryptedData = EncryptData(paddedData, ssc);
            Console.WriteLine("[DOTNET] Encrypted data: " + BitConverter.ToString(encryptedData).Replace("-", " "));

            // 3. Bygg DO'87'
            byte[] do87 = BuildDO87(encryptedData);
            Console.WriteLine("[DOTNET] DO'87': " + BitConverter.ToString(do87).Replace("-", " "));

            // 4. Bygg data för MAC-beräkning
            byte[] paddedHeader = new byte[] { 0x0C, 0xA4, 0x02, 0x0C, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] dataToMac = ConcatenateArrays(paddedHeader, do87);
            Console.WriteLine("[DOTNET] cmdHeader+DO87: " + BitConverter.ToString(dataToMac).Replace("-", " "));

            // Padda hela M-strängen
            dataToMac = PadData(dataToMac);
            Console.WriteLine("[DOTNET] Padded data to MAC: " + BitConverter.ToString(dataToMac).Replace("-", " "));

            // 5. Beräkna MAC
            byte[] mac = CalculateMAC(dataToMac, ssc);
            Console.WriteLine("[DOTNET] Calculated MAC: " + BitConverter.ToString(mac).Replace("-", " "));

            // 6. Bygg DO'8E'
            byte[] do8E = BuildDO8E(mac);
            Console.WriteLine("[DOTNET] DO'8E': " + BitConverter.ToString(do8E).Replace("-", " "));

            // 7. Bygg final protected APDU
            byte[] protectedApdu = BuildProtectedAPDU(paddedHeader, do87, do8E);

            Console.WriteLine("[DOTNET] Protected APDU: " + BitConverter.ToString(protectedApdu).Replace("-", " "));

            var response = _isoDep.Transceive(protectedApdu);
            Console.WriteLine("[DOTNET] reponse: " + BitConverter.ToString(response).Replace("-", " "));

            // 8.Öka SSC för response verifiering
            IncrementSSC(ref ssc);
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(ssc).Replace("-", " "));

            try
            {
                VerifyResponse(response, ssc, _ksMac);
                Console.WriteLine("Response verification successful");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Response verification failed: {ex.Message}");
            }
            return response;
        }

        private byte[] PadData(byte[] data)
        {
            int paddingLength = 16 - (data.Length % 16);
            byte[] paddedData = new byte[data.Length + paddingLength];
            Buffer.BlockCopy(data, 0, paddedData, 0, data.Length);
            paddedData[data.Length] = 0x80;
            return paddedData;
        }

        private byte[] EncryptData(byte[] paddedData, byte[] ssc)
        {
            Console.WriteLine("[DOTNET] SSC value before EncryptData: " + BitConverter.ToString(ssc).Replace("-", " "));
            using (Aes aes = Aes.Create())
            {
                aes.Key = _ksEnc;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                // För PACE: IV är krypterad SSC
                byte[] iv = CalculateIV(ssc);
                Console.WriteLine("[DOTNET] Calculated IV: " + BitConverter.ToString(iv).Replace("-", " "));
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(paddedData, 0, paddedData.Length);
                }
            }
        }

        private byte[] CalculateIV(byte[]_ssc)
        {
            Console.WriteLine("[DOTNET] SSC value before CalculateIV: " + BitConverter.ToString(_ssc).Replace("-", " "));
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

        private byte[] CalculateMAC(byte[] data, byte[] ssc)
        {
            Console.WriteLine("[DOTNET] SSC value before CalculateMAC: " + BitConverter.ToString(ssc).Replace("-", " "));

            // För PACE: Använd AES-CMAC
            // Först konkatenera SSC
            byte[] macInput = ConcatenateArrays(ssc, data);
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
            byte[] protectedApdu = header.Take(4) // Notera: P2 = 0x0C här
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

        private void IncrementSSC(ref byte[] _ssc)
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

        private void VerifyResponse(byte[] response, byte[] SSC, byte[] KSMac)
        {
            // Extrahera DO'99' och DO'8E'
            byte[] DO99 = null;
            byte[] responseMac = null;
            int index = 0;

            while (index < response.Length - 2)
            {
                byte tag = response[index];
                byte length = response[index + 1];

                if (tag == 0x99)
                {
                    DO99 = new byte[2 + length];
                    Array.Copy(response, index, DO99, 0, 2 + length);
                    index += 2 + length;
                }
                else if (tag == 0x8E)
                {
                    responseMac = new byte[length];
                    Array.Copy(response, index + 2, responseMac, 0, length);
                    break;
                }
                else
                {
                    index++;
                }
            }
            Console.WriteLine("extracted DO99: " + BitConverter.ToString(DO99).Replace("-", " "));
            Console.WriteLine("extracted responseMac: " + BitConverter.ToString(responseMac).Replace("-", " "));

            if (DO99 == null || responseMac == null)
                throw new Exception("Invalid response format");

            // Beräkna MAC för verifiering
            byte[] macInput = DO99;
            Console.WriteLine("macInput (DO99): " + BitConverter.ToString(macInput).Replace("-", " "));

            byte[] paddedMacInput = PadData(macInput);
            Console.WriteLine("paddedMacInput: " + BitConverter.ToString(paddedMacInput).Replace("-", " "));

            byte[] calculatedMac = CalculateMAC(paddedMacInput, SSC);
            Console.WriteLine("calculatedMac: " + BitConverter.ToString(calculatedMac).Replace("-", " "));

            bool isEqual = calculatedMac.SequenceEqual(responseMac);
            if (isEqual)
                Console.WriteLine($"{BitConverter.ToString(calculatedMac)} == {BitConverter.ToString(responseMac)}: {isEqual}");

            //if (!calculatedMac.SequenceEqual(responseMac))
            //Console.WriteLine("Response MAC verification failed");
            //throw new Exception("Response MAC verification failed");
        }
    }
}
