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
using Xamarin.Google.Crypto.Tink.Subtle;
using Microsoft.Maui.Controls;
using Xamarin.Google.Crypto.Tink.Shaded.Protobuf;

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
                    isoDep.Timeout = 20000;

                    byte[] selectApdu = new byte[] {
                        0x00, // CLA
                        0xA4, // INS - INS (Instruction) field, specifying the operation to be performed, which is application selection.
                        0x04, // P1
                        0x0C, // P2 (Corrected)
                        0x07, // Lc (Length of AID)
                        0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01,
                        0x00// AID
                    };
                    Console.WriteLine($"selectApdu: {BitConverter.ToString(selectApdu)}");
                    byte[] response = isoDep.Transceive(selectApdu);
                    if (!IsSuccessfulResponse(response))
                    {
                        Console.WriteLine("Failed to select passport application.");
                        isoDep.Close();
                        return;
                    }

                    Console.WriteLine("Application selected.");

                    Console.WriteLine("Performing BAC...");
       
                    string mrzData = "";

                    var (KEnc, KMac) = BacHelper.GenerateBacKeys(mrzData);


                    if (KEnc == null || KMac == null || KEnc.Length != 16 || KMac.Length != 16)
                    {
                        Console.WriteLine("Invalid BAC keys derived.");
                        isoDep.Close();
                        return;
                    }

                    //byte[] enc = { 0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2 };
                    //byte[] mac = { 0x79, 0x62, 0xD9, 0xEC, 0xE0, 0x3D, 0x1A, 0xCD, 0x4C, 0x76, 0x08, 0x9D, 0xCE, 0x13, 0x15, 0x43 };
                    //Console.WriteLine("Kenc--" + BitConverter.ToString(enc));
                    //Console.WriteLine("Kmac--" + BitConverter.ToString(mac));


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
                //--------------------------------------------------------------------1. Request an 8 byte random number from the eMRTD’s contactless IC
                byte[] challengeCommand = new byte[] { 0x00, 0x84, 0x00, 0x00, 0x08 };
                byte[] challengeResponse = isoDep.Transceive(challengeCommand);
                Console.WriteLine($"challengeCommand: {BitConverter.ToString(challengeCommand)}");

                if (!IsSuccessfulResponse(challengeResponse))
                {
                    Console.WriteLine("Failed to get challenge response.");
                    return false;
                }
                Console.WriteLine($"Challenge response length: {challengeResponse.Length}");
                Console.WriteLine($"Challenge response: {BitConverter.ToString(challengeResponse)}");

                byte[] rndIc = challengeResponse.Take(challengeResponse.Length - 2).ToArray();
                Console.WriteLine($"rndIc response length: {rndIc.Length}");
                Console.WriteLine($"rndIc response: {BitConverter.ToString(rndIc)}");

                if (rndIc.Length != 8)
                {
                    Console.WriteLine("Invalid challenge response length.");
                    return false;
                }

                //--------------------------------------------------------------------2. Generate an 8 byte random and a 16 byte random
                RandomNumberGenerator rng = RandomNumberGenerator.Create();

                // Generera RND.IFD (8 bytes)
                byte[] rndIfd = new byte[8];
                rng.GetBytes(rndIfd);
                Console.WriteLine($"RND.IFD: {BitConverter.ToString(rndIfd)}");

                // Generera KIFD (16 bytes)
                byte[] kIfd = new byte[16];
                rng.GetBytes(kIfd);
                Console.WriteLine($"KIFD: {BitConverter.ToString(kIfd)}");


                //--------------------------------------------------------------------3.Concatenate RND.IFD, RND.IC and KIFD
                byte[] s = rndIfd.Concat(rndIc).Concat(kIfd).ToArray();
                Console.WriteLine($"S: {BitConverter.ToString(s)}");

                //byte[] ss = { 0x78, 0x17, 0x23, 0x86, 0x0C, 0x06, 0xC2, 0x26, 0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12, 0x0B, 0x79, 0x52, 0x40, 0xCB, 0x70, 0x49, 0xB0, 0x1C, 0x19, 0xB3, 0x3E, 0x32, 0x80, 0x4F, 0x0B };

                //--------------------------------------------------------------------4.Encrypt S with 3DES key KEnc:
                byte[] Eifd = EncryptWithKEnc3DES(s, KEnc);
                Console.WriteLine($"(Eifd) Encrypted S: {BitConverter.ToString(Eifd)}");


                //--------------------------------------------------------------------5. Compute MAC over EIFD with 3DES key KMAC: MIFD = ‘5F1448EEA8AD90A7’
                byte[] MIFD = ComputeMac3DES(Eifd, KMac);
                Console.WriteLine($"(MAC) Generated MIFD: {BitConverter.ToString(MIFD)}");


                //-------------------------------------------------------------------- 6.Construct command data for EXTERNAL AUTHENTICATE and send command APDU to the eMRTD’s contactless IC
                byte[] cmd_data = Eifd.Concat(MIFD).ToArray();
                Console.WriteLine($"cmd_data: {BitConverter.ToString(cmd_data)}");

                //new byte[6 + cmd_data.Length] betyder: new byte[46]
                byte[] apduCommand = new byte[6 + cmd_data.Length];
                apduCommand[0] = 0x00;  // CLA
                apduCommand[1] = 0x82;  // INS
                apduCommand[2] = 0x00;  // P1
                apduCommand[3] = 0x00;  // P2
                apduCommand[4] = (byte)cmd_data.Length;  // Lc
                Array.Copy(cmd_data, 0, apduCommand, 5, cmd_data.Length);  // Kopiera cmd_data (källa, KällanstartIndex,destination, destinIndex,längden)
                apduCommand[5 + cmd_data.Length] = 0x28;  // Le

                Console.WriteLine($"apduCommand: {BitConverter.ToString(apduCommand)}");

                // Skicka kommandot till kortet
                byte[] apduResponse = isoDep.Transceive(apduCommand);

                Console.WriteLine($"APDU Response: {BitConverter.ToString(apduResponse)}");




                if (!IsSuccessfulResponse(apduResponse))
                {
                    Console.WriteLine($"apduResponse failed.{BitConverter.ToString(apduResponse)}");
                    return false;
                }

                Console.WriteLine("apduResponse succeeded.");
                return true;

                //--------------------------------------------------------------------------------------------------

                //byte[] decryptedChallenge = DecryptWithKEnc(s, KEnc);
                //Console.WriteLine($"Decrypted challenge: {BitConverter.ToString(decryptedChallenge)}");

                //byte[] mutualAuthCommand = BuildMutualAuthCommand(decryptedChallenge, KEnc, KMac);
                //byte[] mutualAuthResponse = isoDep.Transceive(mutualAuthCommand);

                //if (!IsSuccessfulResponse(mutualAuthResponse))
                //{
                //    Console.WriteLine("Mutual authentication failed.");
                //    return false;
                //}

                //Console.WriteLine("Mutual authentication succeeded.");
                //return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"BAC authentication error: {ex.Message}");
                return false;
            }
        }

        //private byte[] DecryptWithKEnc(byte[] data, byte[] KEnc)
        //{
        //    using (var aes = Aes.Create())
        //    {
        //        aes.Key = KEnc;
        //        aes.Mode = CipherMode.CBC;
        //        aes.Padding = PaddingMode.None;
        //        aes.IV = new byte[16];

        //        using (var decryptor = aes.CreateDecryptor())
        //        {
        //            return decryptor.TransformFinalBlock(data, 0, data.Length);
        //        }
        //    }
        //}

        //private byte[] BuildMutualAuthCommand(byte[] challenge, byte[] KEnc, byte[] KMac)
        //{
        //    byte[] encryptedChallenge = EncryptWithKEnc(challenge, KEnc);
        //    byte[] mac = ComputeMac(encryptedChallenge, KMac);

        //    return encryptedChallenge.Concat(mac).ToArray();
        //}


        private byte[] EncryptWithKEnc3DES(byte[] data, byte[] KEnc)
        {
            using (var tripleDes = TripleDES.Create())
            {
                tripleDes.Key = KEnc;               // 3DES-nyckel (24 bytes)
                tripleDes.Mode = CipherMode.CBC;    // CBC-läge
                tripleDes.Padding = PaddingMode.None; // Ingen padding
                tripleDes.IV = new byte[8];         // IV sätts till 8 nollbytes (3DES använder 8-byte block)

                // Padding till blockstorlek (8 bytes för 3DES)
                int blockSize = 8;
                int paddedLength = (data.Length + blockSize - 1) / blockSize * blockSize;
                byte[] paddedData = new byte[paddedLength];
                Array.Copy(data, paddedData, data.Length);

                using (var encryptor = tripleDes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(paddedData, 0, paddedData.Length);
                }
            }
        }



        //private byte[] EncryptWithKEnc(byte[] data, byte[] KEnc)
        //{
        //    using (var aes = Aes.Create())
        //    {
        //        aes.Key = KEnc;
        //        aes.Mode = CipherMode.CBC;
        //        aes.Padding = PaddingMode.None;
        //        aes.IV = new byte[16];

        //        using (var encryptor = aes.CreateEncryptor())
        //        {
        //            return encryptor.TransformFinalBlock(data, 0, data.Length);
        //        }
        //    }
        //}

        public static byte[] ComputeMac3DES(byte[] eifd, byte[] KMac)
        {
            if (KMac.Length != 16 && KMac.Length != 24)
                throw new ArgumentException("Key length must be 16 or 24 bytes for 3DES");

            // Dela upp nyckeln för 3DES
            byte[] key1 = new byte[8];
            byte[] key2 = new byte[8];
            Array.Copy(KMac, 0, key1, 0, 8);
            Array.Copy(KMac, 8, key2, 0, 8);

            using (var des1 = DES.Create())
            using (var des2 = DES.Create())
            {
                des1.Key = key1;
                des1.Mode = CipherMode.CBC;
                des1.Padding = PaddingMode.None;
                des1.IV = new byte[8];

                des2.Key = key2;
                des2.Mode = CipherMode.CBC;
                des2.Padding = PaddingMode.None;
                des2.IV = new byte[8];

                // Lägg till padding till EIFD
                byte[] paddedData = PadIso9797Method2(eifd);

                // MAC steg 1: Kryptera med nyckel 1
                byte[] intermediate = des1.CreateEncryptor().TransformFinalBlock(paddedData, 0, paddedData.Length);

                // MAC steg 2: Dekryptera slutet med nyckel 2
                byte[] finalBlock = des2.CreateDecryptor().TransformFinalBlock(intermediate, intermediate.Length - 8, 8);

                // MAC steg 3: Kryptera igen med nyckel 1
                byte[] mac = des1.CreateEncryptor().TransformFinalBlock(finalBlock, 0, 8);

                // Returnera de första 8 byten av MAC
                byte[] result = new byte[8];
                Array.Copy(mac, 0, result, 0, 8);
                return result;
            }
        }

        private static byte[] PadIso9797Method2(byte[] data)
        {
            int blockSize = 8;
            int paddedLength = ((data.Length + blockSize) / blockSize) * blockSize;
            byte[] paddedData = new byte[paddedLength];
            Array.Copy(data, paddedData, data.Length);
            paddedData[data.Length] = 0x80; // Längdbyte
            return paddedData;
        }





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
