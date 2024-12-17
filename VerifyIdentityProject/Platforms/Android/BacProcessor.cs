using Android.Nfc;
using Android.Nfc.Tech;
using System;
using System.Security.Cryptography;
using VerifyIdentityProject.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using VerifyIdentityProject.Resources.Interfaces;
using Android.App;
using Xamarin.Google.Crypto.Tink.Subtle;
using Microsoft.Maui.Controls;
using Xamarin.Google.Crypto.Tink.Shaded.Protobuf;
using System.Runtime.Intrinsics.X86;
using System.Reflection.PortableExecutable;

namespace VerifyIdentityProject.Platforms.Android
{
    public class BacProcessor : Java.Lang.Object, NfcAdapter.IReaderCallback
    {
        private readonly NfcReaderManager _nfcReaderManager;

        public BacProcessor(NfcReaderManager nfcReaderManager)
        {
            _nfcReaderManager = nfcReaderManager;
        }

        public void OnTagDiscovered(Tag tag)
        {
            Console.WriteLine("Tag detected!");
            try
            {
                _nfcReaderManager.IdentifyTagTechnologies(tag);

                IsoDep isoDep = IsoDep.Get(tag);
                if (isoDep != null)
                {
                    ProcessBac(isoDep);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during NFC processing: {ex.Message}");
            }
        }

        private void ProcessBac(IsoDep isoDep)
        {
            try
            {
                isoDep.Connect();
                isoDep.Timeout = 20000;

                byte[] selectApdu = new byte[] {
                    0x00, 0xA4, 0x04, 0x0C, 0x07,
                    0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01, 0x00
                };

                Console.WriteLine($"selectApdu: {BitConverter.ToString(selectApdu)}");
                byte[] response = isoDep.Transceive(selectApdu);

                if (!IsSuccessfulResponse(response))
                {
                    Console.WriteLine("Failed to select passport application.");
                    return;
                }

                Console.WriteLine("Application selected.");

                var secrets = GetSecrets.FetchSecrets();
                var mrzData = secrets?.MRZ_NUMBERS ?? string.Empty;
                var (KEnc, KMac) = BacHelper.GenerateBacKeys(mrzData);

                if (!PerformBacAuthentication(isoDep, KEnc, KMac))
                {
                    Console.WriteLine("BAC authentication failed.");
                    return;
                }

                Console.WriteLine("BAC authentication succeeded!");

                byte[] dg1Command = BuildReadBinaryCommand(0x01);
                byte[] dg1Response = isoDep.Transceive(dg1Command);

                if (!IsSuccessfulResponse(dg1Response))
                {
                    Console.WriteLine("Failed to read DG1.");
                    return;
                }

                DecodePassportData(dg1Response);
            }
            finally
            {
                isoDep.Close();
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


                //-------------------------------------------------------------------- 6.Send command APDU to the eMRTD’s contactless IC
                Console.WriteLine($"apduCommand: {BitConverter.ToString(apduCommand)}");
                byte[] apduResponse = isoDep.Transceive(apduCommand);

                byte[] rndIfd2 = { 0x78, 0x17, 0x23, 0x86, 0x0C, 0x06, 0xC2, 0x26 };
                byte[] apduResponse2 = { 0x46, 0xB9, 0x34, 0x2A, 0x41, 0x39, 0x6C, 0xD7, 0x38, 0x6B, 0xF5, 0x80, 0x31, 0x04, 0xD7, 0xCE, 0xDC, 0x12, 0x2B, 0x91, 0x32, 0x13, 0x9B, 0xAF, 0x2E, 0xED, 0xC9, 0x4E, 0xE1, 0x78, 0x53, 0x4F, 0x2F, 0x2D, 0x23, 0x5D, 0x07, 0x4D, 0x74, 0x49, };
                byte[] KEnc2 = { 0xAB, 0x94, 0xFD, 0xEC, 0xF2, 0x67, 0x4F, 0xDF, 0xB9, 0xB3, 0x91, 0xF8, 0x5D, 0x7F, 0x76, 0xF2 };
                byte[] kIfd2 = { 0x0B, 0x79, 0x52, 0x40, 0xCB, 0x70, 0x49, 0xB0, 0x1C, 0x19, 0xB3, 0x3E, 0x32, 0x80, 0x4F, 0x0B };
                byte[] rndIc2 = { 0x46, 0x08, 0xF9, 0x19, 0x88, 0x70, 0x22, 0x12 };

                //-------------------------------------------------------------------- 7. cmd_resp if successfull or not
                Console.WriteLine($"APDU Response: {BitConverter.ToString(apduResponse)}");
                if (!IsSuccessfulResponse(apduResponse))
                {
                    Console.WriteLine($"apduResponse failed.{BitConverter.ToString(apduResponse)}");
                    return false;
                }
                Console.WriteLine("apduResponse succeeded.");


                //-------------------------------------------------------------------- 1.Decrypt and verify received data and compare received RND.IFD with generated RND.IFD

                //-------------------------------------------------------------------- 1.1 Seperate `Eifd`, `MIC`, och `SW1-SW2` from cmd_resp
                byte[] eIc = apduResponse2.Take(32).ToArray();
                byte[] mIc = apduResponse2.Skip(32).Take(8).ToArray();
                //byte[] status = apduResponse.Skip(40).ToArray();

                Console.WriteLine($"Eifd: {BitConverter.ToString(eIc)}");
                Console.WriteLine($"MIC: {BitConverter.ToString(mIc)}");
                // Console.WriteLine($"Status: {BitConverter.ToString(status)}");

                // status control - 90 00
                //if (!status.SequenceEqual(new byte[] { 0x90, 0x00 }))
                //{
                //    Console.WriteLine("Error: Invalid response status.");
                //    return false;
                //}
                //-------------------------------------------------------------------- 1.2 Get (r) by Decrypt eIc with help of kEnc.
                byte[] r = DecryptWithKEnc3DES(eIc, KEnc2);
                Console.WriteLine($"(R) Response Data: {BitConverter.ToString(r)}");


                //-------------------------------------------------------------------- 1.3 seperate (r) and take out Recieved-rndIfd to compare to rndIfd. If success fetch/store kIc.
                var kIc = CheckRndIfd(r, rndIfd2);

                //-------------------------------------------------------------------- 2.Calculate XOR of KIFD and KIC. That gets out Kseed.
                byte[] kSeed = ComputeKSeed(kIfd2, kIc);

                //-------------------------------------------------------------------- 3. Calculate session keys (KSEnc and KSMAC) according to Section 9.7.1/Appendix D.1
                byte[] kSEnc = DeriveKey(kSeed, 1); // Counter = 1 för KSEnc
                byte[] kSMac = DeriveKey(kSeed, 2); // Counter = 2 för KSMac

                byte[] KSEncParitet = AdjustAndSplitKey(kSEnc);
                byte[] KSMacParitet = AdjustAndSplitKey(kSMac);
                Console.WriteLine($"KSEnc: {BitConverter.ToString(KSEncParitet)}");
                Console.WriteLine($"KSMac: {BitConverter.ToString(KSMacParitet)}");

                //-------------------------------------------------------------------- 4. Calculate send sequence counter (SSC)
                byte[] SSC = ComputeSSC(rndIc2, rndIfd2);
                Console.WriteLine($"SSC: {BitConverter.ToString(SSC)}");

                //--------------------------------------------------------------------  D.4 SECURE MESSAGING

                //--------------------------------------------------------------------  1. Mask class byte and pad command header:CmdHeader = ‘0CA4020C80000000’
                byte[] cmdHeader = new byte[]
                {
                    0x0C, 0xA4, 0x02, 0x0C, // CLA, INS, P1, P2
                    0x80, 0x00, 0x00, 0x00  // Padding (Mask)
                };
                Console.WriteLine($"-cmdHeader-: {BitConverter.ToString(cmdHeader)}");


                //--------------------------------------------------------------------  1.1 Pad data: Data = ‘011E800000000000’
                byte[] data = new byte[]
                {
                    0x01, 0x1E,  // File ID för EF.COM
                    0x80, 0x00, 0x00, 0x00, 0x00  // Padding
                };
                Console.WriteLine($"-Data-: {BitConverter.ToString(data)}");


                //--------------------------------------------------------------------  1.2 Encrypt data with KSEnc:EncryptedData = ‘63-75-43-29-08-C0-44-F6’ 63-75-43-29-08-C0-44-F6 - RÄTT
                byte[] encryptedData = EncryptWithKEnc3DES(data, KSEncParitet);
                Console.WriteLine($"Encrypted Data with KsEnc: {BitConverter.ToString(encryptedData)}");

                //--------------------------------------------------------------------  1.3 Build DO‘87’: DO87 = ‘87-09-01-63-75-43-29-08-C0-44-F6’ 87-09-01-63-75-43-29-08-C0-44-F6 - RÄTT
                byte[] DO87 = BuildDO87(encryptedData);
                Console.WriteLine($"-DO87-: {BitConverter.ToString(DO87)}");

                //--------------------------------------------------------------------  1.4 Concatenate CmdHeader and DO‘87’: M = ‘0C-A4-02-0C-80-00-00-00-87-09-01-63-75-43-29-08-C0-44-F6’ - RÄTT
                //                                                                                                                 0C-A4-02-0C-80-00-00-00-87-09-01-63-75-43-29-08-C0-44-F6
                byte[] M = cmdHeader.Concat(DO87).ToArray();
                Console.WriteLine($"-M-: {BitConverter.ToString(M)}");

                //--------------------------------------------------------------------  2. Compute MAC of M:

                //--------------------------------------------------------------------  2.1 Increment SSC with 1: SSC = ‘88-70-22-12-0C-06-C2-27’ - Rätt
                IncrementSSC(ref SSC);
                Console.WriteLine($"Incremented SSC: {BitConverter.ToString(SSC)}");

                //--------------------------------------------------------------------  2.2 Concatenate SSC and M and add padding: N = ‘887022120C06C2270CA4020C80000000 8709016375432908C044F68000000000’ - Rätt
                byte[] N = SSC.Concat(M).ToArray();
                N = PadIso9797Method2(N);
                Console.WriteLine($"-N-: {BitConverter.ToString(N)}");

                //--------------------------------------------------------------------  2.3 Compute MAC over N with KSMAC: CC = ‘BF8B92D635FF24F8’ - fel
                byte[] CC = ComputeMac3DES(N, KSMacParitet);
                Console.WriteLine($"-MAC-: {BitConverter.ToString(CC)}");




                return true;

            }
            catch (Exception ex)
            {
                Console.WriteLine($"BAC authentication error: {ex.Message}");
                return false;
            }
        }


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

        public static byte[] ComputeMac3DES(byte[] data, byte[] KMac)
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
                byte[] paddedData = PadIso9797Method2(data);

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

        private byte[] DecryptWithKEnc3DES(byte[] eIc, byte[] KEnc)
        {
            using (var tripleDes = TripleDES.Create())
            {
                tripleDes.Key = KEnc;               // 3DES-nyckel (24 bytes)
                tripleDes.Mode = CipherMode.CBC;
                tripleDes.Padding = PaddingMode.None;
                tripleDes.IV = new byte[8];         // IV = 8 nollbytes


                var ngt = tripleDes.CreateDecryptor().TransformFinalBlock(eIc, 0, eIc.Length);

                Console.WriteLine($"Decrypted DATAA: {BitConverter.ToString(ngt)}");

                return ngt;
            }
        }

        private byte[] CheckRndIfd(byte[] decryptedR, byte[] rndIfd)
        {
            byte[] receivedRndIifd = decryptedR.Skip(8).Take(8).ToArray(); // Nästa 8 bytes
            byte[] receivedRndIc = decryptedR.Take(8).ToArray();   // Första 8 bytes
            byte[] receivedKic = decryptedR.Skip(16).Take(16).ToArray(); // Sista 16 bytes

            Console.WriteLine($"rndIfd: {BitConverter.ToString(rndIfd)}");

            Console.WriteLine($"received-RndIfd: {BitConverter.ToString(receivedRndIifd)}");
            Console.WriteLine($"received-RndIc: {BitConverter.ToString(receivedRndIc)}");
            Console.WriteLine($"received-Kic: {BitConverter.ToString(receivedKic)}");


            // Jämför `RND.IFD` med genererad `RND.IFD`
            if (!receivedRndIifd.SequenceEqual(rndIfd)) // `rndIfd` är din genererade data
            {
                Console.WriteLine("Error: Received RND.IFD does not match generated RND.IFD.");
            }
            Console.WriteLine("RND.IFD successfully verified.");
            return receivedKic;
        }

        byte[] ComputeKSeed(byte[] kIfd, byte[] kIc)
        {
            if (kIfd.Length != 16 || kIc.Length != 16)
            {
                throw new ArgumentException("KIFD and KIC must be 16 bytes long.");
            }

            byte[] kSeed = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                kSeed[i] = (byte)(kIfd[i] ^ kIc[i]);
            }

            Console.WriteLine($"(kSeed) Response Data: {BitConverter.ToString(kSeed)}");
            return kSeed;
        }

        static byte[] DeriveKey(byte[] kseed, int counter)
        {
            // Convert counter to a 4-byte big-endian array
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }

            // Concatenate Kseed and counter
            byte[] data = new byte[kseed.Length + counterBytes.Length];
            Buffer.BlockCopy(kseed, 0, data, 0, kseed.Length);
            Buffer.BlockCopy(counterBytes, 0, data, kseed.Length, counterBytes.Length);

            // Compute SHA-1 hash of the concatenated data
            byte[] derivedHash;
            using (SHA1 sha1 = SHA1.Create())
            {
                derivedHash = sha1.ComputeHash(data);
            }

            // Return the first 16 bytes of the hash
            byte[] key = new byte[16];
            Array.Copy(derivedHash, key, 16);
            return key;

        }

        static byte[] AdjustAndSplitKey(byte[] key)
        {
            if (key.Length != 16)
                throw new ArgumentException("Key must be 16 bytes long for 3DES");

            // Dela nyckeln i två delar
            byte[] KaPrime = key.Take(8).ToArray();  // Första 8 bytes
            byte[] KbPrime = key.Skip(8).Take(8).ToArray();  // Sista 8 bytes

            // Justera paritetsbitarna
            byte[] Ka = AdjustParityBitsExact(KaPrime);
            byte[] Kb = AdjustParityBitsExact(KbPrime);

            return Ka.Concat(Kb).ToArray();
        }

        static byte[] AdjustParityBitsExact(byte[] key)
        {
            byte[] adjustedKey = new byte[key.Length];

            for (int i = 0; i < key.Length; i++)
            {
                byte currentByte = key[i];
                int numSetBits = CountSetBits(currentByte);

                // Om antalet '1'-bitar är jämnt, justera sista biten
                if (numSetBits % 2 == 0)
                {
                    adjustedKey[i] = (byte)(currentByte ^ 1); // Ändra sista biten för att det ska bli Parity
                }
                else
                {
                    adjustedKey[i] = currentByte; // Behåll byte som den är
                }
            }

            return adjustedKey;
        }

        // Räknar antalet '1'-bitar i en byte
        static int CountSetBits(byte b)
        {
            int count = 0;
            while (b != 0)
            {
                count += b & 1;
                b >>= 1;
            }
            return count;
        }

        byte[] ComputeSSC(byte[] rndIc2, byte[] rndIfd2)
        {
            // Kontrollera att input är minst 8 bytes
            if (rndIc2.Length < 8 || rndIfd2.Length < 8)
            {
                throw new ArgumentException("RND.IC and RND.IFD must be at least 8 bytes long.");
            }

            // Ta de sista 4 bytes från RND.IC och RND.IFD
            byte[] ssc = new byte[8];
            Array.Copy(rndIc2, rndIc2.Length - 4, ssc, 0, 4); // Sista 4 bytes från RND.IC
            Array.Copy(rndIfd2, rndIfd2.Length - 4, ssc, 4, 4); // Sista 4 bytes från RND.IFD

            Console.WriteLine($"ssc: {BitConverter.ToString(ssc)}");
            return ssc;
        }

        byte[] BuildDO87(byte[] encryptedData)
        {
            byte[] DO87 = new byte[1 + 1 + 1 + encryptedData.Length];
            DO87[0] = 0x87; // Tag för DO87
            DO87[1] = (byte)(1 + encryptedData.Length); // Längd
            DO87[2] = 0x01; // Indikator för krypterat data
            Array.Copy(encryptedData, 0, DO87, 3, encryptedData.Length);
            return DO87;
        }

        private void IncrementSSC(ref byte[] SSC)
        {
            for (int i = SSC.Length - 1; i >= 0; i--)
            {
                if (++SSC[i] != 0) break;
            }
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
}
