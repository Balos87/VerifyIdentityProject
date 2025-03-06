using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    public class SecureMessagingHelper
    {
        public byte[] _ksEnc;
        public byte[] _ksMac;
        public byte[] _ssc;
        public Dictionary<string, string> _dictionaryMrzData;

        public SecureMessagingHelper(byte[] ksEnc, byte[] ksMac)
        {
            _ksEnc = ksEnc;
            _ksMac = ksMac;
            _ssc = new byte[16];
        }


        public byte[] PadDataPace(byte[] data)
        {
            int paddingLength = 16 - (data.Length % 16);
            byte[] paddedData = new byte[data.Length + paddingLength];
            Buffer.BlockCopy(data, 0, paddedData, 0, data.Length);
            paddedData[data.Length] = 0x80;
            return paddedData;
        }

        public byte[] DecryptDataPace(byte[] paddedData, byte[] ssc)
        {
            Console.WriteLine("SSC value before EncryptData: " + BitConverter.ToString(ssc).Replace("-", " "));
            using (Aes aes = Aes.Create())
            {
                aes.Key = _ksEnc;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                // För PACE: IV är krypterad SSC
                byte[] iv = CalculateIVPace(ssc);
                Console.WriteLine("Calculated IV: " + BitConverter.ToString(iv).Replace("-", " "));
                aes.IV = iv;

                var decryptedData = aes.CreateDecryptor().TransformFinalBlock(paddedData, 0, paddedData.Length);

                return decryptedData;
            }
        }

        public byte[] EncryptDataPace(byte[] paddedData, byte[] ssc)
        {
            Console.WriteLine("SSC value before EncryptData: " + BitConverter.ToString(ssc).Replace("-", " "));
            using (Aes aes = Aes.Create())
            {
                aes.Key = _ksEnc;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;

                // För PACE: IV är krypterad SSC
                byte[] iv = CalculateIVPace(ssc);
                Console.WriteLine("Calculated IV: " + BitConverter.ToString(iv).Replace("-", " "));
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(paddedData, 0, paddedData.Length);
                }
            }
        }

        public byte[] CalculateIVPace(byte[] _ssc)
        {
            Console.WriteLine("SSC value before CalculateIV: " + BitConverter.ToString(_ssc).Replace("-", " "));
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

        public byte[] CalculateMACPace(byte[] data, byte[] ssc)
        {
            Console.WriteLine("SSC value before CalculateMAC: " + BitConverter.ToString(ssc).Replace("-", " "));

            // För PACE: Använd AES-CMAC
            // Först konkatenera SSC
            byte[] macInput = ConcatenateArraysPace(ssc, data);
            Console.WriteLine("Full MAC input with SSC: " + BitConverter.ToString(macInput).Replace("-", " "));

            var cipher = new AesEngine();
            var mac = new CMac(cipher, 128);
            mac.Init(new KeyParameter(_ksMac));
            mac.BlockUpdate(macInput, 0, macInput.Length);

            byte[] fullMac = new byte[16];
            mac.DoFinal(fullMac, 0);

            return fullMac.Take(8).ToArray();
        }

        public byte[] BuildProtectedAPDUPace(byte[] header, byte[] do87, byte[] do8E)
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

        public byte[] BuildDO87Pace(byte[] encryptedData)
        {
            return new byte[] { 0x87 }
                .Concat(new byte[] { (byte)(encryptedData.Length + 1) })
                .Concat(new byte[] { 0x01 })
                .Concat(encryptedData)
                .ToArray();
        }

        public byte[] BuildDO8EPace(byte[] mac)
        {
            return new byte[] { 0x8E, 0x08 }
                .Concat(mac)
                .ToArray();
        }

        public void IncrementSSCPace(ref byte[] _ssc)
        {
            for (int i = _ssc.Length - 1; i >= 0; i--)
            {
                if (++_ssc[i] != 0)
                    break;
            }

        }

        public byte[] ConcatenateArraysPace(params byte[][] arrays)
        {
            return arrays.SelectMany(x => x).ToArray();
        }

        public void VerifyResponsePace(byte[] response, byte[] SSC, byte[] KSMac)
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

            byte[] paddedMacInput = PadDataPace(macInput);
            Console.WriteLine("paddedMacInput: " + BitConverter.ToString(paddedMacInput).Replace("-", " "));

            byte[] calculatedMac = CalculateMACPace(paddedMacInput, SSC);
            Console.WriteLine("calculatedMac: " + BitConverter.ToString(calculatedMac).Replace("-", " "));

            bool isEqual = calculatedMac.SequenceEqual(responseMac);
            if (isEqual)
                Console.WriteLine($"{BitConverter.ToString(calculatedMac)} == {BitConverter.ToString(responseMac)}: {isEqual}");

        }

        public bool IsSuccessfulResponsePace(byte[] response)
        {
            Console.WriteLine("<-IsSuccessfulResponse->");
            if (response == null || response.Length < 2)
                return false;

            // Check the last two bytes for the status code
            return response[response.Length - 2] == 0x90 && response[response.Length - 1] == 0x00;
        }
    }
}
