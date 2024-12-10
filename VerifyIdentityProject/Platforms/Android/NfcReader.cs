using Android.Nfc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using VerifyIdentityProject.Resources.Interfaces;
using Android.App;
using Android.Nfc.Tech;
using VerifyIdentityProject.Helpers;
using System.Security.Cryptography;

namespace VerifyIdentityProject.Platforms.Android
{
    internal class NfcReader : INfcReader
    {
        private NfcAdapter _nfcAdapter;
        private Activity _activity;

        public NfcReader()
        {
            _activity = Platform.CurrentActivity!;
            _nfcAdapter = NfcAdapter.GetDefaultAdapter(_activity);
        }

        public void StartListening()
        {
            if (_nfcAdapter == null || !_nfcAdapter.IsEnabled)
            {
                Console.WriteLine("NFC not supported or not enabled.");
                return;
            }
            //byta till nfcb?
            _nfcAdapter.EnableReaderMode(_activity, new NfcReaderCallback(), NfcReaderFlags.NfcB | NfcReaderFlags.SkipNdefCheck, null);
        }

        public void StopListening()
        {
            _nfcAdapter.DisableReaderMode(_activity);
        }
    }

    public class NfcReaderCallback : Java.Lang.Object, NfcAdapter.IReaderCallback
    {
        public void OnTagDiscovered(Tag tag)
        {
            try
            {
                IsoDep isoDep = IsoDep.Get(tag);
                if (isoDep != null)
                {
                    isoDep.Connect();
                    //ta bort sista 0x00?
                    byte[] selectApdu = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01, 0x00 };
                    byte[] response = isoDep.Transceive(selectApdu);
                    if (!IsSuccessfulResponse(response))
                    {
                        Console.WriteLine("Failed to select passport application.");
                        isoDep.Close();
                        return;
                    }

                    Console.WriteLine("Application selected.");

                    Console.WriteLine("Performing BAC...");

                    string mrzData = "";  // Passnummer + Födelsedatum + Utgångsdatum

                    var (KEnc, KMac) = BacHelper.GenerateBacKeys(mrzData);

                    Console.WriteLine($"Derived Keys:\nKEnc: {BitConverter.ToString(KEnc)}\nKMac: {BitConverter.ToString(KMac)}");

                    if (KEnc == null || KMac == null || KEnc.Length != 16 || KMac.Length != 16)
                    {
                        Console.WriteLine("Invalid BAC keys derived.");
                        isoDep.Close();
                        return;
                    }

                    if (!PerformBacAuthentication(isoDep, KEnc, KMac))
                    {
                        Console.WriteLine("BAC authentication failed.");
                        isoDep.Close();
                        return;
                    }

                    Console.WriteLine("BAC authentication succeeded!");

                    byte[] dg1Command = BuildReadBinaryCommand(0x01);
                    byte[] dg1Response = isoDep.Transceive(dg1Command);
                    if (!IsSuccessfulResponse(dg1Response))
                    {
                        Console.WriteLine("Failed to read DG1.");
                        isoDep.Close();
                        return;
                    }

                    DecodePassportData(dg1Response);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during NFC processing: {ex.Message}");
            }
        }

        private bool PerformBacAuthentication(IsoDep isoDep, byte[] KEnc, byte[] KMac)
        {
            try
            {
                byte[] challengeCommand = new byte[] { 0x00, 0x84, 0x00, 0x00, 0x08 };
                byte[] challengeResponse = isoDep.Transceive(challengeCommand);

                Console.WriteLine($"Challenge response length: {challengeResponse.Length}");
                if (!IsSuccessfulResponse(challengeResponse))
                {
                    Console.WriteLine("Failed to get challenge response.");
                    return false;
                }

                byte[] decryptedChallenge = DecryptWithKEnc(challengeResponse, KEnc);
                Console.WriteLine($"Decrypted challenge: {BitConverter.ToString(decryptedChallenge)}");

                byte[] mutualAuthCommand = BuildMutualAuthCommand(decryptedChallenge, KEnc, KMac);


                byte[] mutualAuthResponse = isoDep.Transceive(mutualAuthCommand);



                Console.WriteLine($"MutualAuthResponse Length: {mutualAuthResponse.Length}");
                Console.WriteLine($"MutualAuthResponse Data: {BitConverter.ToString(mutualAuthResponse)}");



                if (!IsSuccessfulResponse(mutualAuthResponse))
                {
                    Console.WriteLine("Mutual authentication failed.");
                    return false;
                }

                Console.WriteLine("Mutual authentication succeeded.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"BAC authentication error: {ex.Message}");
                return false;
            }
        }

        private byte[] DecryptWithKEnc(byte[] data, byte[] KEnc)
        {
            // Pad the data to 16 bytes
            int blockSize = 16;
            int paddedLength = (data.Length + blockSize - 1) / blockSize * blockSize;
            byte[] paddedData = new byte[paddedLength];
            Array.Copy(data, paddedData, data.Length);

            Console.WriteLine($"Padded Data: {BitConverter.ToString(paddedData)}");

            using (var aes = Aes.Create())
            {
                aes.Key = KEnc;
                aes.Mode = CipherMode.CBC; //changed from EBC to CBC
                aes.Padding = PaddingMode.None;
                aes.IV = new byte[16];

                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(paddedData, 0, paddedData.Length);
                }
            }
        }


        private byte[] BuildMutualAuthCommand(byte[] challenge, byte[] KEnc, byte[] KMac)
        {
            // Kryptera challenge med KEnc
            byte[] encryptedChallenge = EncryptWithKEnc(challenge, KEnc);

            Console.WriteLine($"Encrypted Challenge: {BitConverter.ToString(encryptedChallenge)}");
            Console.WriteLine($"Encrypted Challenge Length: {encryptedChallenge.Length}");

            Console.WriteLine($"Data for MAC: {BitConverter.ToString(encryptedChallenge)}");

            // Beräkna MAC på krypterad challenge
            byte[] mac = ComputeMac(encryptedChallenge, KMac);

            Console.WriteLine($"MAC: {BitConverter.ToString(mac)}");
            Console.WriteLine($"MAC Length: {mac.Length}");

            // Bygg hela kommandot: krypterad challenge + MAC
            byte[] mutualAuthCommand = encryptedChallenge.Concat(mac).ToArray();

            Console.WriteLine($"MutualAuthCommand Length: {mutualAuthCommand.Length}");
            Console.WriteLine($"MutualAuthCommand Data: {BitConverter.ToString(mutualAuthCommand)}");



            return mutualAuthCommand;
        }


        private byte[] EncryptWithKEnc(byte[] data, byte[] KEnc)
        {
            // Pad the data to a multiple of 16 bytes (AES block size)
            int blockSize = 16;
            int paddedLength = (data.Length + blockSize - 1) / blockSize * blockSize;
            byte[] paddedData = new byte[paddedLength];
            Array.Copy(data, paddedData, data.Length);
            Console.WriteLine($"Padded Data: {BitConverter.ToString(paddedData)}");

            using (var aes = Aes.Create())
            {
                aes.Key = KEnc;
                aes.Mode = CipherMode.CBC; // Ändrat till CBC-läge
                aes.Padding = PaddingMode.None;
                aes.IV = new byte[16];

                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(paddedData, 0, paddedData.Length);
                }
            }
        }

        private byte[] ComputeMac(byte[] data, byte[] KMac)
        {
            using (var hmac = new HMACSHA1(KMac))
            {
                byte[] mac = hmac.ComputeHash(data);
                Console.WriteLine($"Generated MAC: {BitConverter.ToString(mac)}");
                return mac.Take(8).ToArray();  // Ta de första 8 byte för MAC
            }
        }


        //Kontrollerar om svaret är korrekt enligt ISO 7816-4 (APDU-kommandon)
        private bool IsSuccessfulResponse(byte[] response)
        {
            return response.Length >= 2 && response[^2] == 0x90 && response[^1] == 0x00;
        }








        private byte[] BuildReadBinaryCommand(int fileId)
        {
            return new byte[] { 0x00, 0xB0, (byte)((fileId >> 8) & 0xFF), (byte)(fileId & 0xFF), 0x00 };
        }

        private void DecodePassportData(byte[] data)
        {
            var parser = new Asn1DerParser();
            parser.Parse(data);
        }
    }

    public class Asn1DerParser
    {
        public void Parse(byte[] data)
        {
            int index = 0;

            while (index < data.Length)
            {
                if (index + 2 > data.Length)
                {
                    Console.WriteLine("Malformed ASN.1 data.");
                    break;
                }

                byte tag = data[index++];
                Console.WriteLine($"Tag: {tag:X2}");

                int length = ReadLength(data, ref index);
                Console.WriteLine($"Length: {length}");

                if (index + length > data.Length)
                {
                    Console.WriteLine("Invalid length specified.");
                    break;
                }

                byte[] value = data.Skip(index).Take(length).ToArray();
                index += length;

                Console.WriteLine($"Value: {BitConverter.ToString(value)}");

                if ((tag & 0x20) == 0x20)
                {
                    Console.WriteLine("Parsing constructed type...");
                    Parse(value);
                }
                else
                {
                    if (tag == 0x0C)
                    {
                        Console.WriteLine($"Decoded String: {Encoding.UTF8.GetString(value)}");
                    }
                }
            }
        }

        private int ReadLength(byte[] data, ref int index)
        {
            int length = data[index++];
            if ((length & 0x80) == 0x80)
            {
                int lengthBytes = length & 0x7F;
                length = 0;
                for (int i = 0; i < lengthBytes; i++)
                {
                    length = (length << 8) | data[index++];
                }
            }
            return length;
        }
    }
}
