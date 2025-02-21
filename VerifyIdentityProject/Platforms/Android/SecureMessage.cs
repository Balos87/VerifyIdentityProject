using Android.Nfc.Tech;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureMessage
    {
        private readonly IsoDep _isoDep;
        private readonly byte[] _ksEnc;
        private readonly byte[] _ksMac;
        private byte[] _ssc;

        public SecureMessage(byte[] ksEnc, byte[] ksMac, IsoDep isoDep)
        {
            _ksEnc = ksEnc;
            _ksMac = ksMac;
            _isoDep = isoDep;
            InitializeSSC();
        }

        public bool PerformSecureMessage()
        {
            Console.WriteLine("-------------------------------------Secure Messaging started..");
            try
            {
                byte[] selectApdu = new byte[]
                {
                    0x0C,                                    // CLA (Secure Messaging)
                    0xA4,                                    // INS (SELECT)
                    0x04,                                    // P1
                    0x0C,                                    // P2
                    0x07,                                    // Lc (length of AID)
                    0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 // AID - notera att vi inte inkluderar Le här
                };

                // Skydda och skicka kommandot
                byte[] protectedApdu = ProtectAPDU(selectApdu);
                Console.WriteLine($"Protected selectApdu: {BitConverter.ToString(protectedApdu)}");

                byte[] response = _isoDep.Transceive(protectedApdu);

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

        private byte[] ProtectAPDU(byte[] apdu)
        {
            Console.WriteLine($"Initial SSC: {BitConverter.ToString(_ssc)}");
            Console.WriteLine($"KSEnc: {BitConverter.ToString(_ksEnc)}");
            Console.WriteLine($"KSMac: {BitConverter.ToString(_ksMac)}");

            // Extrahera kommandodata (utan Le)
            byte[] commandData = null;
            if (apdu.Length > 5)
            {
                int dataLength = apdu[4];  // Lc
                commandData = new byte[dataLength];
                Array.Copy(apdu, 5, commandData, 0, dataLength);
            }

            // Först, beräkna IV (innan SSC incrementas)
            byte[] iv = CalculateIV();
            Console.WriteLine($"IV: {BitConverter.ToString(iv)}");

            // Nu kan vi incrementa SSC för MAC beräkning
            IncrementSSC();

            // Padda och kryptera data
            byte[] paddedData = PadData(commandData);
            byte[] encryptedData = EncryptData(paddedData, iv);
            Console.WriteLine($"Encrypted Data: {BitConverter.ToString(encryptedData)}");

            // Bygg dataobjekt
            byte[] do87 = BuildDO87(encryptedData);
            Console.WriteLine($"DO87: {BitConverter.ToString(do87)}");

            // Le ska vara null här för att indikera att vi vill ha allt tillbaka
            byte[] do97 = BuildDO97(0x00);

            // Beräkna MAC
            byte[] header = new byte[] { apdu[0], apdu[1], apdu[2], apdu[3] };
            byte[] mac = CalculateMAC(header, do87, do97);
            Console.WriteLine($"MAC: {BitConverter.ToString(mac)}");

            byte[] do8E = BuildDO8E(mac);

            // Kombinera allt
            return CombineAll(apdu[0], apdu[1], do87, do97, do8E);
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
            int blockSize = 16;
            int paddedLength = ((data.Length + blockSize) / blockSize) * blockSize;
            byte[] paddedData = new byte[paddedLength];
            Array.Copy(data, paddedData, data.Length);
            paddedData[data.Length] = 0x80; // Längdbyte
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
            return new byte[] { 0x97, 0x01, 0x00 };  // Le = 00 för maximal längd
        }

        private byte[] CalculateMAC(byte[] header, byte[] do87, byte[] do97)
        {
            using (var ms = new MemoryStream())
            {
                // SSC
                ms.Write(_ssc, 0, _ssc.Length);

                // Command Header
                ms.Write(header, 0, 4);

                // Total längd inklusive DO'8E' (8 bytes MAC + 2 bytes header)
                int totalLength = (do87?.Length ?? 0) + (do97?.Length ?? 0) + 10;
                ms.WriteByte((byte)totalLength);

                // Data Objects i rätt ordning
                if (do87.Length > 0)
                    ms.Write(do87, 0, do87.Length);
                if (do97.Length > 0)
                    ms.Write(do97, 0, do97.Length);

                byte[] input = ms.ToArray();
                Console.WriteLine($"MAC Input: {BitConverter.ToString(input)}");
                return CalculateCMAC(input);
            }
        }

        private byte[] CalculateCMAC(byte[] data)
        {
            var cmac = new CMac(new AesEngine());
            cmac.Init(new KeyParameter(_ksMac));
            byte[] result = new byte[cmac.GetMacSize()];
            cmac.BlockUpdate(data, 0, data.Length);
            cmac.DoFinal(result, 0);
            return result.Take(8).ToArray(); // Ta bara 8 bytes enligt specifikationen
        }

        private byte[] BuildDO8E(byte[] mac)
        {
            byte[] do8E = new byte[mac.Length + 2];
            do8E[0] = 0x8E;
            do8E[1] = 0x08;  // MAC length är alltid 8 bytes
            Array.Copy(mac, 0, do8E, 2, mac.Length);
            return do8E;
        }

        private byte[] CombineAll(byte cla, byte ins, byte[] do87, byte[] do97, byte[] do8E)
        {
            using (var ms = new MemoryStream())
            {
                // Header
                ms.WriteByte(cla);
                ms.WriteByte(ins);
                ms.WriteByte(0x04);  // P1
                ms.WriteByte(0x0C);  // P2

                // Beräkna total längd
                int totalLength = (do87?.Length ?? 0) + (do97?.Length ?? 0) + do8E.Length;
                ms.WriteByte((byte)totalLength);

                // Data objects i rätt ordning
                if (do87.Length > 0) ms.Write(do87, 0, do87.Length);
                if (do97.Length > 0) ms.Write(do97, 0, do97.Length);
                ms.Write(do8E, 0, do8E.Length);

                return ms.ToArray();
            }
        }

        private void InitializeSSC()
        {
            _ssc = new byte[16];  // 16 bytes av nollor för AES
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
    }
}