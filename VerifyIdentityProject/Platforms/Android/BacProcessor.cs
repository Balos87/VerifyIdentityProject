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
using System.Runtime.Intrinsics.Arm;
using Xamarin.Google.Crypto.Tink.Util;
using Xamarin.Google.Crypto.Tink.Prf;
using Java.Lang.Ref;
using Android.Media.TV;
using Android.Graphics;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.IO;
using static AndroidX.Concurrent.Futures.CallbackToFutureAdapter;
using static Android.Graphics.PathIterator;





#if ANDROID
using static Android.OS.Environment;
using static Android.Provider.MediaStore;
using static Android.App.Application;
using Android.Content;
#endif

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
                PaceProcessor.PerformPace(isoDep);
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
                isoDep.Timeout = 40000;

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

                var (KSEncParitet, KSMacParitet, SSC) = PerformBacAuthentication(isoDep, KEnc, KMac);
                Console.WriteLine("BAC authentication succeeded!");

                //--------------------------------------------------------------------  D.4 SECURE MESSAGING

                Console.WriteLine("-------------------------------------------------Starting DG2");
                //DG2 method
                CallDG2.Call(isoDep, KSEncParitet, KSMacParitet, SSC);
                Console.WriteLine("-------------------------------------------------Starting DG1");
                //DG1 method
                CallDG1.Call(isoDep, KSEncParitet, KSMacParitet, SSC);


            }
            finally
            {
                isoDep.Close();
            }
        }

        private (byte[] KSEncParitet, byte[] KSMacParitet, byte[] SSC) PerformBacAuthentication(IsoDep isoDep, byte[] KEnc, byte[] KMac)
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
                    throw new Exception("Failed to get challenge response.");
                }
                Console.WriteLine($"Challenge response length: {challengeResponse.Length}");
                Console.WriteLine($"Challenge response: {BitConverter.ToString(challengeResponse)}");

                byte[] rndIc = challengeResponse.Take(challengeResponse.Length - 2).ToArray();
                Console.WriteLine($"rndIc response length: {rndIc.Length}");
                Console.WriteLine($"rndIc response: {BitConverter.ToString(rndIc)}");

                if (rndIc.Length != 8)
                {
                    Console.WriteLine("Invalid challenge response length.");
                    throw new Exception("Invalid challenge response length.");

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


                //-------------------------------------------------------------------- 7. cmd_resp if successfull or not
                Console.WriteLine($"APDU Response: {BitConverter.ToString(apduResponse)}");
                if (!IsSuccessfulResponse(apduResponse))
                {
                    Console.WriteLine($"apduResponse failed.{BitConverter.ToString(apduResponse)}");
                    throw new Exception($"apduResponse failed.{BitConverter.ToString(apduResponse)}");

                }
                Console.WriteLine("apduResponse succeeded.");


                //-------------------------------------------------------------------- 1.Decrypt and verify received data and compare received RND.IFD with generated RND.IFD

                //-------------------------------------------------------------------- 1.1 Seperate `Eifd`, `MIC`, och `SW1-SW2` from cmd_resp
                byte[] eIc = apduResponse.Take(32).ToArray();
                byte[] mIc = apduResponse.Skip(32).Take(8).ToArray();

                Console.WriteLine($"Eifd: {BitConverter.ToString(eIc)}");
                Console.WriteLine($"MIC: {BitConverter.ToString(mIc)}");

                //-------------------------------------------------------------------- 1.2 Get (r) by Decrypt eIc with help of kEnc.
                byte[] r = DecryptWithKEnc3DES(eIc, KEnc);
                Console.WriteLine($"(R) Response Data: {BitConverter.ToString(r)}");


                //-------------------------------------------------------------------- 1.3 seperate (r) and take out Recieved-rndIfd to compare to rndIfd. If success fetch/store kIc.
                var kIc = CheckRndIfd(r, rndIfd);

                //-------------------------------------------------------------------- 2.Calculate XOR of KIFD(my random 16 byte random) and KIC. That gets out Kseed.
                byte[] kSeed = ComputeKSeed(kIfd, kIc);

                //-------------------------------------------------------------------- 3. Calculate session keys (KSEnc and KSMAC) according to Section 9.7.1/Appendix D.1                      -Rätt
                //                                                                        KSEnc: 97-9E-C1-3B-1C-BF-E9-DC-D0-1A-B0-FE-D3-07-EA-E5 KSMac: F1-CB-1F-1F-B5-AD-F2-08-80-6B-89-DC-57-9D-C1-F8
                byte[] kSEnc = DeriveKey(kSeed, 1); // Counter = 1 för KSEnc
                byte[] kSMac = DeriveKey(kSeed, 2); // Counter = 2 för KSMac

                byte[] KSEncParitet = AdjustAndSplitKey(kSEnc);
                byte[] KSMacParitet = AdjustAndSplitKey(kSMac);
                Console.WriteLine($"KSEnc: {BitConverter.ToString(KSEncParitet)}");
                Console.WriteLine($"KSMac: {BitConverter.ToString(KSMacParitet)}");

                //-------------------------------------------------------------------- 4. Calculate send sequence counter (SSC) = ‘88-70-22-12-0C-06-C2-26’ -  88-70-22-12-0C-06-C2-26  -- RÄTT
                byte[] SSC = ComputeSSC(rndIc, rndIfd);
                Console.WriteLine($"SSC: {BitConverter.ToString(SSC)}");


                return (KSEncParitet, KSMacParitet, SSC);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"BAC authentication error: {ex.Message}");
                throw new Exception($"BAC authentication error: {ex.Message}");

            }
        }
        //----------------------------------------------------------------------- K och CC rätt
        public static byte[] ExtractImageFromDG2(byte[] dg2Data)
        {
            try
            {
                // Ladda DG2 som ASN.1-struktur
                Asn1InputStream asn1Stream = new Asn1InputStream(dg2Data);
                var asn1Object = asn1Stream.ReadObject();

                // Hämta den sekvens som innehåller JPEG
                Asn1Sequence dg2Sequence = asn1Object as Asn1Sequence;
                if (dg2Sequence == null) throw new Exception("Felaktig DG2-struktur.");

                // Iterera genom noderna för att hitta JPEG
                foreach (var obj in dg2Sequence)
                {
                    if (obj is Asn1OctetString octetString)
                    {
                        byte[] imageData = octetString.GetOctets();
                        if (IsJPEGData(imageData)) return imageData;
                    }
                }

                throw new Exception("Ingen JPEG-data hittades i DG2.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid ASN.1-parsning: {ex.Message}");
                throw;
            }
        }

        private static bool IsJPEGData(byte[] data)
        {
            // Kontrollera om datan börjar med JPEG-startmarkör (0xFF, 0xD8) och slutar med JPEG-slutmarkör (0xFF, 0xD9)
            return data.Length > 4 &&
                   data[0] == 0xFF &&
                   data[1] == 0xD8 &&
                   data[data.Length - 2] == 0xFF &&
                   data[data.Length - 1] == 0xD9;
        }
        public class CallDG1
        {
            public static void Call(IsoDep isoDep, byte[] KSEncParitet, byte[] KSMacParitet, byte[] SSC)
            {
                //--------------------------------------------------------------------  1. Mask class byte and pad command header:CmdHeader = ‘0C-A4-02-0C-80-00-00-00’ - 0C-A4-02-0C-80-00-00-00 -- RÄTT
                byte[] cmdHeader = new byte[]
                {
                    0x0C, 0xA4, 0x02, 0x0C, // CLA, INS, P1, P2
                    0x80, 0x00, 0x00, 0x00  // Padding (Mask)
                };
                Console.WriteLine($"-cmdHeader-: {BitConverter.ToString(cmdHeader)}");


                //--------------------------------------------------------------------  1.1 Pad data: Data = ‘01-1E-80-00-00-00-00-00’ - 01-1E-80-00-00-00-00-00 - RÄTT
                byte[] data = new byte[]
                {
                    0x01, 0x01,  // File ID för EF.COM:1E?/DG1:01?/DG2:02?
                };
                byte[] paddedData = PadIso9797Method2(data);
                Console.WriteLine($"-Data-: {BitConverter.ToString(paddedData)}");


                //--------------------------------------------------------------------  1.2 Encrypt data with KSEnc:EncryptedData = ‘63-75-43-29-08-C0-44-F6’ - Recieved: 63-75-43-29-08-C0-44-F6 -- RÄTT
                byte[] encryptedData = EncryptWithKEnc3DES(paddedData, KSEncParitet);
                Console.WriteLine($"Encrypted Data with KsEnc: {BitConverter.ToString(encryptedData)}");

                //--------------------------------------------------------------------  1.3 Build DO‘87’: DO87 = ‘87-09-01-63-75-43-29-08-C0-44-F6’ - Recieved: 87-09-01-63-75-43-29-08-C0-44-F6 -- RÄTT
                byte[] DO87 = BuildDO87(encryptedData);
                Console.WriteLine($"-DO87-: {BitConverter.ToString(DO87)}");

                //--------------------------------------------------------------------  1.4 Concatenate CmdHeader and DO‘87’: M = ‘0C-A4-02-0C-80-00-00-00-87-09-01-63-75-43-29-08-C0-44-F6’ -- RÄTT
                //                                                                                                       Recieved: 0C-A4-02-0C-80-00-00-00-87-09-01-63-75-43-29-08-C0-44-F6
                byte[] M = cmdHeader.Concat(DO87).ToArray();
                Console.WriteLine($"-M-: {BitConverter.ToString(M)}");

                //--------------------------------------------------------------------  2. Compute MAC of M:


                //--------------------------------------------------------------------  2.1 Increment SSC with 1: SSC = ‘88-70-22-12-0C-06-C2-27’ -- Rätt
                IncrementSSC(ref SSC);
                Console.WriteLine($"Incremented SSC: {BitConverter.ToString(SSC)}");

                //-------------------------------------------------------------------- 2.2 Concatenate SSC + M + padding: N = 88-70-22-12-0C-06-C2-27-0C-A4-02-0C-80-00-00-00-87-09-01-63-75-43-29-08-C0-44-F6-80-00-00-00-00
                //                                                                                                  Recieved: 88-70-22-12-0C-06-C2-27-0C-A4-02-0C-80-00-00-00-87-09-01-63-75-43-29-08-C0-44-F6-80-00-00-00-00 -- Rätt
                byte[] NNopad = SSC.Concat(M).ToArray();
                byte[] N = PadIso9797Method2(NNopad);
                Console.WriteLine($"-N-: {BitConverter.ToString(N)}");

                //--------------------------------------------------------------------  2.3 Compute MAC over N with KSMAC: CC = ‘BF-8B-92-D6-35-FF-24-F8’ - Recieved: BF-8B-92-D6-35-FF-24-F8 -- RÄTT
                byte[] CC = ComputeMac3DES(NNopad, KSMacParitet); //use with no pad so compute can work!
                Console.WriteLine($"-N Nopad-: {BitConverter.ToString(NNopad)}");
                Console.WriteLine($"-CC- (MAC over N with KSMAC): {BitConverter.ToString(CC)}");


                //--------------------------------------------------------------------  3. Build DO‘8E’ - 8E-08-BF-8B-92-D6-35-FF-24-F8 - Recieved: 8E-08-BF-8B-92-D6-35-FF-24-F8 -- RÄTT
                byte[] DO8E = BuildDO8E(CC);
                Console.WriteLine($"DO8E: {BitConverter.ToString(DO8E)}");


                //--------------------------------------------------------------------  3. Construct & send protected APDU: ProtectedAPDU = ‘0C-A4-02-0C-15-87-09-01-63-75-43-29-08-C0-44-F6-8E-08-BF-8B-92-D6-35-FF-24-F8-00’--RÄTT
                //                                                                                                                 Recieved: 0C-A4-02-0C-15-87-09-01-63-75-43-29-08-C0-44-F6-8E-08-BF-8B-92-D6-35-FF-24-F8-00 
                byte[] protectedAPDU = ConstructProtectedAPDU(cmdHeader, DO87, DO8E);
                Console.WriteLine($"Protected APDU: {BitConverter.ToString(protectedAPDU)}");

                //---------------------------------------------------------------------- Send and  Receive response APDU of eMRTD’s contactless IC: RAPDU = ‘99-02-90-00-8E-08-FA-85-5A-5D-4C-50-A8-ED-90-00’ ?- RÄTT
                //                                                                                                 Dummy data wont work here since it gets 69-88. But works with my passport
                byte[] RAPDU = isoDep.Transceive(protectedAPDU);
                Console.WriteLine($"APDU Response: {BitConverter.ToString(RAPDU)}");


                //----------------------------------------------------------------------- 4. Verify RAPDU CC by computing MAC of DO‘99’:

                //----------------------------------------------------------------------- 4.1 Increment SSC with 1:SSC = ‘88-70-22-12-0C-06-C2-28’ - Recieved: 88-70-22-12-0C-06-C2-28  -- RÄTT
                IncrementSSC(ref SSC);
                Console.WriteLine($"Incremented SSC (RAPDU ): {BitConverter.ToString(SSC)}");

                //----------------------------------------------------------------------- 4.2 Concatenate SSC and DO‘99’ and add padding: K = ‘88-70-22-12-0C-06-C2-28-99-02-90-00-80-00-00-00 -- RÄTT
                //                                                                                                                   Recieved: 88-70-22-12-0C-06-C2-28-99-02-90-00-80-00-00-00
                byte[] DO99 = new byte[] { 0x99, 0x02, 0x90, 0x00 };
                Console.WriteLine($"DO99: {BitConverter.ToString(DO99)}");

                byte[] K = PadIso9797Method2(SSC.Concat(DO99).ToArray());
                Console.WriteLine($"(K) Padded data for MAC: {BitConverter.ToString(K)}");

                //----------------------------------------------------------------------- 4.3 Compute MAC with KSMAC: CC’ = ‘FA-85-5A-5D-4C-50-A8-ED - Recievied: FA-85-5A-5D-4C-50-A8-ED -- RÄTT
                byte[] kNoPad = SSC.Concat(DO99).ToArray(); //removed pad so compute can work!
                byte[] ccMac = ComputeMac3DES(kNoPad, KSMacParitet);
                Console.WriteLine($"(CC) Computed MAC: {BitConverter.ToString(ccMac)}");

                //----------------------------------------------------------------------- 4.4 Compare CC’ with data of DO‘8E’ of RAPDU. ‘FA855A5D4C50A8ED’ == ‘FA855A5D4C50A8ED’ ? YES. -- RÄTT
                var extractedDO8E = ExtractDO8E(RAPDU);
                bool isEqual = ccMac.SequenceEqual(extractedDO8E);
                if (isEqual)
                    Console.WriteLine($"CC' == DO‘8E’: {isEqual}");
                Console.WriteLine($"extracted DO8E: {BitConverter.ToString(extractedDO8E)} = CC: {BitConverter.ToString(ccMac)}");




                //----------------------------------------------------------------------- 1 Read Binary of first four bytes
                Console.WriteLine("/----------------------------------------------------------------------- 1 Read Binary of first four bytes");
                List<byte[]> dg1Segments = ReadCompleteDG(isoDep, KSEncParitet, KSMacParitet, ref SSC);
                if (dg1Segments.Count > 0)
                {
                    byte[] completeDG1 = dg1Segments.SelectMany(segment => segment).ToArray();
                    Console.WriteLine($"Complete DG1 Data: {BitConverter.ToString(completeDG1)}");
                    Console.WriteLine($"Complete DG1 Data.Length: {completeDG1.Length}");

                    // Skriv ut första och sista bytes för att verifiera
                    Console.WriteLine($"First 20 bytes: {BitConverter.ToString(completeDG1.Take(20).ToArray())}");
                    Console.WriteLine($"Last 20 bytes: {BitConverter.ToString(completeDG1.Skip(completeDG1.Length - 20).Take(20).ToArray())}");

                    // Om du behöver se all data, kan du skriva ut i chunks
                    const int chunkSize = 100;
                    for (int i = 0; i < completeDG1.Length; i += chunkSize)
                    {
                        int length = Math.Min(chunkSize, completeDG1.Length - i);
                        var chunk = new byte[length];
                        Array.Copy(completeDG1, i, chunk, 0, length);
                        Console.WriteLine($"Chunk {i / chunkSize}: {BitConverter.ToString(chunk)}");
                    }

                    Console.WriteLine($"Parsed nya");
                    var fullMrz = MRZByteParser.ParseMRZBytes(completeDG1);
                    var splittedMrz = MRZByteParser.FormatMRZForBAC(fullMrz);
                    Console.WriteLine($"Hel MRZ: {fullMrz}");
                    Console.WriteLine($"Delad MRZ:\n {splittedMrz}");

                    var extractedInfoFromMrz = MRZParser.ParseMRZ(splittedMrz);

                    var extractedInfoWithDescription = MRZParser.ToDictionary(extractedInfoFromMrz);

                    var parsedMRZ = ParseMRZ(splittedMrz);

                    foreach (var field in extractedInfoWithDescription)
                    {
                        Console.WriteLine($"{field.Key}: {field.Value}");
                    }
                }
                Console.WriteLine("/----------------------------------------------------------------------- DG1 process finished!");

            }
        }

        public class CallDG2
        {
            public static void Call(IsoDep isoDep, byte[] KSEncParitet, byte[] KSMacParitet, byte[] SSC)
            {
                //--------------------------------------------------------------------  1. Mask class byte and pad command header:CmdHeader = ‘0C-A4-02-0C-80-00-00-00’ - 0C-A4-02-0C-80-00-00-00 -- RÄTT
                byte[] cmdHeader = new byte[]
                { // CLA, INS,   P1,   P2
                    0x0C, 0xA4, 0x02, 0x0C, 
                    0x80, 0x00, 0x00, 0x00  // Padding (Mask)
                };
                Console.WriteLine($"-cmdHeader-: {BitConverter.ToString(cmdHeader)}");


                //--------------------------------------------------------------------  1.1 Pad data: Data = ‘01-1E-80-00-00-00-00-00’ - 01-1E-80-00-00-00-00-00 - RÄTT
                byte[] data = new byte[]
                {
                    0x01, 0x02,  // File ID för EF.COM:1E?/DG1:01?/DG2:02?
                };
                byte[] paddedData = PadIso9797Method2(data);
                Console.WriteLine($"-Data-: {BitConverter.ToString(paddedData)}");


                //--------------------------------------------------------------------  1.2 Encrypt data with KSEnc:EncryptedData = ‘63-75-43-29-08-C0-44-F6’ - Recieved: 63-75-43-29-08-C0-44-F6 -- RÄTT
                byte[] encryptedData = EncryptWithKEnc3DES(paddedData, KSEncParitet);
                Console.WriteLine($"Encrypted Data with KsEnc: {BitConverter.ToString(encryptedData)}");

                //--------------------------------------------------------------------  1.3 Build DO‘87’: DO87 = ‘87-09-01-63-75-43-29-08-C0-44-F6’ - Recieved: 87-09-01-63-75-43-29-08-C0-44-F6 -- RÄTT
                byte[] DO87 = BuildDO87(encryptedData);
                Console.WriteLine($"-DO87-: {BitConverter.ToString(DO87)}");

                //--------------------------------------------------------------------  1.4 Concatenate CmdHeader and DO‘87’: M = ‘0C-A4-02-0C-80-00-00-00-87-09-01-63-75-43-29-08-C0-44-F6’ -- RÄTT
                //                                                                                                       Recieved: 0C-A4-02-0C-80-00-00-00-87-09-01-63-75-43-29-08-C0-44-F6
                byte[] M = cmdHeader.Concat(DO87).ToArray();
                Console.WriteLine($"-M-: {BitConverter.ToString(M)}");

                //--------------------------------------------------------------------  2. Compute MAC of M:


                //--------------------------------------------------------------------  2.1 Increment SSC with 1: SSC = ‘88-70-22-12-0C-06-C2-27’ -- Rätt
                IncrementSSC(ref SSC);
                Console.WriteLine($"Incremented SSC: {BitConverter.ToString(SSC)}");

                //-------------------------------------------------------------------- 2.2 Concatenate SSC + M + padding: N = 88-70-22-12-0C-06-C2-27-0C-A4-02-0C-80-00-00-00-87-09-01-63-75-43-29-08-C0-44-F6-80-00-00-00-00
                //                                                                                                  Recieved: 88-70-22-12-0C-06-C2-27-0C-A4-02-0C-80-00-00-00-87-09-01-63-75-43-29-08-C0-44-F6-80-00-00-00-00 -- Rätt
                byte[] NNopad = SSC.Concat(M).ToArray();
                byte[] N = PadIso9797Method2(NNopad);
                Console.WriteLine($"-N-: {BitConverter.ToString(N)}");

                //--------------------------------------------------------------------  2.3 Compute MAC over N with KSMAC: CC = ‘BF-8B-92-D6-35-FF-24-F8’ - Recieved: BF-8B-92-D6-35-FF-24-F8 -- RÄTT
                byte[] CC = ComputeMac3DES(NNopad, KSMacParitet); //use with no pad so compute can work!
                Console.WriteLine($"-N Nopad-: {BitConverter.ToString(NNopad)}");
                Console.WriteLine($"-CC- (MAC over N with KSMAC): {BitConverter.ToString(CC)}");


                //--------------------------------------------------------------------  3. Build DO‘8E’ - 8E-08-BF-8B-92-D6-35-FF-24-F8 - Recieved: 8E-08-BF-8B-92-D6-35-FF-24-F8 -- RÄTT
                byte[] DO8E = BuildDO8E(CC);
                Console.WriteLine($"DO8E: {BitConverter.ToString(DO8E)}");


                //--------------------------------------------------------------------  3. Construct & send protected APDU: ProtectedAPDU = ‘0C-A4-02-0C-15-87-09-01-63-75-43-29-08-C0-44-F6-8E-08-BF-8B-92-D6-35-FF-24-F8-00’--RÄTT
                //                                                                                                                 Recieved: 0C-A4-02-0C-15-87-09-01-63-75-43-29-08-C0-44-F6-8E-08-BF-8B-92-D6-35-FF-24-F8-00 
                byte[] protectedAPDU = ConstructProtectedAPDU(cmdHeader, DO87, DO8E);
                Console.WriteLine($"Protected APDU: {BitConverter.ToString(protectedAPDU)}");

                //---------------------------------------------------------------------- Send and  Receive response APDU of eMRTD’s contactless IC: RAPDU = ‘99-02-90-00-8E-08-FA-85-5A-5D-4C-50-A8-ED-90-00’ ?- RÄTT
                //                                                                                                 Dummy data wont work here since it gets 69-88. But works with my passport
                byte[] RAPDU = isoDep.Transceive(protectedAPDU);
                Console.WriteLine($"APDU Response: {BitConverter.ToString(RAPDU)}");

                //----------------------------------------------------------------------- 4. Verify RAPDU CC by computing MAC of DO‘99’:

                //----------------------------------------------------------------------- 4.1 Increment SSC with 1:SSC = ‘88-70-22-12-0C-06-C2-28’ - Recieved: 88-70-22-12-0C-06-C2-28  -- RÄTT
                IncrementSSC(ref SSC);
                Console.WriteLine($"Incremented SSC (RAPDU ): {BitConverter.ToString(SSC)}");

                //----------------------------------------------------------------------- 4.2 Concatenate SSC and DO‘99’ and add padding: K = ‘88-70-22-12-0C-06-C2-28-99-02-90-00-80-00-00-00 -- RÄTT
                //                                                                                                                   Recieved: 88-70-22-12-0C-06-C2-28-99-02-90-00-80-00-00-00
                byte[] DO99 = new byte[] { 0x99, 0x02, 0x90, 0x00 };
                Console.WriteLine($"DO99: {BitConverter.ToString(DO99)}");

                byte[] K = PadIso9797Method2(SSC.Concat(DO99).ToArray());
                Console.WriteLine($"(K) Padded data for MAC: {BitConverter.ToString(K)}");

                //----------------------------------------------------------------------- 4.3 Compute MAC with KSMAC: CC’ = ‘FA-85-5A-5D-4C-50-A8-ED - Recievied: FA-85-5A-5D-4C-50-A8-ED -- RÄTT
                byte[] kNoPad = SSC.Concat(DO99).ToArray(); //removed pad so compute can work!
                byte[] ccMac = ComputeMac3DES(kNoPad, KSMacParitet);
                Console.WriteLine($"(CC) Computed MAC: {BitConverter.ToString(ccMac)}");

                //----------------------------------------------------------------------- 4.4 Compare CC’ with data of DO‘8E’ of RAPDU. ‘FA855A5D4C50A8ED’ == ‘FA855A5D4C50A8ED’ ? YES. -- RÄTT
                var extractedDO8E = ExtractDO8E(RAPDU);
                bool isEqual = ccMac.SequenceEqual(extractedDO8E);
                if (isEqual)
                    Console.WriteLine($"CC' == DO‘8E’: {isEqual}");
                Console.WriteLine($"extracted DO8E: {BitConverter.ToString(extractedDO8E)} = CC: {BitConverter.ToString(ccMac)}");




                //----------------------------------------------------------------------- 1 Read Binary of first four bytes
                Console.WriteLine("/----------------------------------------------------------------------- Read Binary");
                List<byte[]> dg2Segments = ReadCompleteDG(isoDep, KSEncParitet, KSMacParitet, ref SSC);
                Console.WriteLine($"amount returned segment data: {dg2Segments.Count}");

                var completeData = dg2Segments.SelectMany(x => x).ToArray();
                Console.WriteLine($"Complete DG2 Data: {BitConverter.ToString(completeData)}");
                Console.WriteLine($"Complete DG2 Data.length: {completeData.Length}");
                Console.WriteLine($"First 20 bytes: {BitConverter.ToString(completeData.Take(20).ToArray())}");
                Console.WriteLine($"Last 20 bytes: {BitConverter.ToString(completeData.Skip(completeData.Length - 20).Take(20).ToArray())}");

                var bildbit = DG2Parser.ParseDG2(completeData);
                Console.WriteLine($"--------------DG2 {bildbit.Status}");

                Console.WriteLine("/----------------------------------------------------------------------- DG2-data process finished!");

            }
        }

        public class DG2Parser
        {
            public class FaceImageInfo
            {
                public byte[] ImageData { get; set; }
                public string ImageFormat { get; set; }
                public string SavedFilePath { get; set; }
            }

            private class ASN1Length
            {
                public int Length { get; set; }
                public int BytesUsed { get; set; }
            }

            public static async Task<FaceImageInfo> ParseDG2(byte[] rawData, string fileName = "passport_photo")
            {
                try
                {
                    Console.WriteLine($"Starting DG2 parse, total data length: {rawData.Length}");
                    Console.WriteLine($"First 16 bytes: {BitConverter.ToString(rawData.Take(16).ToArray())}");
                    Console.WriteLine($"Last 20 bytes: {BitConverter.ToString(rawData.Skip(rawData.Length - 20).Take(20).ToArray())}");


                    // Hitta och validera DG2 data
                    int offset = 0;
                    while (offset < rawData.Length - 2)
                    {
                        // Leta efter biometrisk information tag (7F61)
                        if (rawData[offset] == 0x7F && rawData[offset + 1] == 0x61)
                        {
                            Console.WriteLine($"Found 7F61 tag at offset: {offset}");
                            break;
                        }
                        offset++;
                    }

                    if (offset >= rawData.Length - 2)
                    {
                        throw new Exception("Kunde inte hitta början av biometrisk data");
                    }

                    // Skippa 7F61 tag
                    offset += 2;

                    // Läs längden på biometrisk data
                    var bioLength = DecodeASN1Length(rawData, offset);
                    offset += bioLength.BytesUsed;

                    Console.WriteLine($"Biometric data length: {bioLength.Length}");

                    // Leta efter bildinformation (5F2E)
                    while (offset < rawData.Length - 2)
                    {
                        if (rawData[offset] == 0x5F && rawData[offset + 1] == 0x2E)
                        {
                            Console.WriteLine($"Found image tag 5F2E at offset: {offset}");
                            break;
                        }
                        offset++;
                    }

                    if (offset >= rawData.Length - 2)
                    {
                        throw new Exception("Kunde inte hitta bilddata");
                    }

                    // Skippa 5F2E tag
                    offset += 2;

                    // Läs längden på bilddata
                    var imageLength = DecodeASN1Length(rawData, offset);
                    offset += imageLength.BytesUsed;

                    Console.WriteLine($"Image data length: {imageLength.Length}");

                    int jpegStart = -1;
                    for (int i = offset; i < rawData.Length - 1; i++)
                    {
                        if (rawData[i] == 0xFF && rawData[i + 1] == 0xD8)
                        {
                            jpegStart = i;
                            Console.WriteLine($"JPEG jpegStart:{jpegStart}");

                            break;
                        }
                    }

                    if (jpegStart == -1)
                    {
                        throw new Exception("Kunde inte hitta JPEG start markör (FF D8)");
                    }

                    // Hitta JPEG slut
                    int jpegEnd = -1;
                    for (int i = jpegStart; i < rawData.Length - 1; i++)
                    {
                        if (rawData[i] == 0xFF && rawData[i + 1] == 0xD9)
                        {
                            jpegEnd = i + 2; // Inkludera FF D9
                            Console.WriteLine($"JPEG jpegEnd:{jpegEnd}");

                            break;
                        }
                    }

                    if (jpegEnd == -1)
                    {
                        throw new Exception("Kunde inte hitta JPEG slut markör (FF D9)");
                    }

                    // Beräkna faktisk JPEG storlek och kopiera datan
                    int jpegLength = jpegEnd - jpegStart;
                    byte[] jpegData = new byte[jpegLength];
                    Array.Copy(rawData, jpegStart, jpegData, 0, jpegLength);

                    // Extrahera bilddata
                    Console.WriteLine($"Raw image data length before copying rawdata over to jpegData: {rawData.Length}");
                    Console.WriteLine($"First 16 bytes before copying rawdata over to jpegData: {BitConverter.ToString(rawData.Take(16).ToArray())}");
                    Console.WriteLine($"Last 20 bytes before copying rawdata over to jpegData: {BitConverter.ToString(rawData.Skip(rawData.Length - 20).Take(20).ToArray())}");

                    Console.WriteLine($"data length after copying rawdata over to jpegData: {jpegData.Length}");
                    Console.WriteLine($"First 16 bytes after copying rawdata over to jpegData: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
                    Console.WriteLine($"Last 20 bytes after copying rawdata over to jpegData: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 20).Take(20).ToArray())}");


                    // Ta bort 80 00 sekvenser
                    jpegData = RemovePadding(jpegData);
                    const int chunkSize = 100;
                    for (int i = 0; i < jpegData.Length; i += chunkSize)
                    {
                        int length = Math.Min(chunkSize, jpegData.Length - i);
                        var chunk = new byte[length];
                        Array.Copy(jpegData, i, chunk, 0, length);
                        Console.WriteLine($"Chunk {i / chunkSize}: {BitConverter.ToString(chunk)}");
                    }
                    Console.WriteLine($"Final JPEG length after padding removal: {jpegData.Length}");
                    Console.WriteLine($"Final JPEG header: {BitConverter.ToString(jpegData.Take(16).ToArray())}");
                    Console.WriteLine($"Final JPEG footer: {BitConverter.ToString(jpegData.Skip(jpegData.Length - 16).Take(16).ToArray())}");

                    var nopad = RemovePadding2(jpegData);
                    Console.WriteLine($"nopad JPEG length after padding removal: {nopad.Length}");

                    if (!IsValidJPEG(nopad))
                    {
                        throw new Exception("Extraherad data är inte en giltig JPEG");
                    }
                    if (jpegData.Length < 100)
                    {
                        throw new Exception($"Misstänkt kort bilddata: {nopad.Length} bytes");
                    }
                    var faceInfo = new FaceImageInfo
                    {
                        ImageData = nopad,
                        ImageFormat = "JPEG"
                    };

                    faceInfo.SavedFilePath = await AutoSaveImage(faceInfo, fileName);
                    Console.WriteLine($"-------------SAVED PATH: {faceInfo.SavedFilePath}");
                    return faceInfo;
                }
                catch (Exception ex)
                {
                    throw new Exception("Fel vid parsning av DG2 data: " + ex.Message, ex);
                }
            }

            public static byte[] RemovePadding2(byte[] input)
            {
                List<byte> result = new List<byte>();

                for (int i = 0; i < input.Length; i++)
                {
                    // Kolla om vi har hittat början på en padding-sekvens
                    if (i <= input.Length - 8 &&  // Se till att vi har nog med bytes kvar att kolla
                        input[i] == 0x80 &&
                        input[i + 1] == 0x00 &&
                        input[i + 2] == 0x00 &&
                        input[i + 3] == 0x00 &&
                        input[i + 4] == 0x00 &&
                        input[i + 5] == 0x00 &&
                        input[i + 6] == 0x00 &&
                        input[i + 7] == 0x00)
                    {
                        // Hoppa över padding-sekvensen
                        i += 7;  // +7 eftersom for-loopen kommer lägga till +1
                        continue;
                    }

                    // Lägg till byte om det inte var del av en padding
                    result.Add(input[i]);
                }

                return result.ToArray();
            }

            private static ASN1Length DecodeASN1Length(byte[] data, int offset)
            {
                if (offset >= data.Length)
                {
                    throw new Exception("Ogiltig offset för ASN.1 längd-avkodning");
                }

                if ((data[offset] & 0x80) == 0)
                {
                    // Kort form
                    return new ASN1Length { Length = data[offset], BytesUsed = 1 };
                }

                // Lång form
                int numLengthBytes = data[offset] & 0x7F;
                if (numLengthBytes > 4)
                {
                    throw new Exception("För lång ASN.1 längd");
                }

                int length = 0;
                for (int i = 0; i < numLengthBytes; i++)
                {
                    length = (length << 8) | data[offset + 1 + i];
                }

                return new ASN1Length { Length = length, BytesUsed = 1 + numLengthBytes };
            }

            private static byte[] RemovePadding(byte[] data)
            {
                // Först, hitta den faktiska JPEG-datan
                int startIndex = -1;
                int endIndex = -1;

                // Hitta JPEG header (FF D8)
                for (int i = 0; i < data.Length - 1; i++)
                {
                    if (data[i] == 0xFF && data[i + 1] == 0xD8)
                    {
                        startIndex = i;
                        Console.WriteLine($"JPEG start index:{startIndex}");
                        break;
                    }
                }

                // Hitta JPEG footer (FF D9)
                Console.WriteLine($"Length of data:{data.Length}");
                for (int i = data.Length - 2; i >= 0; i--)
                {
                    if (data[i] == 0xFF && data[i + 1] == 0xD9)
                    {
                        endIndex = i + 2; // Inkludera FF D9
                        Console.WriteLine($"JPEG end Index:{endIndex}");
                        break;
                    }
                }


                if (startIndex == -1 || endIndex == -1)
                {
                    throw new Exception("Kunde inte hitta giltig JPEG-data");
                }

                // Extrahera bara den faktiska JPEG-datan
                int length = endIndex - startIndex;
                byte[] jpegData = new byte[length];
                Array.Copy(data, startIndex, jpegData, 0, length);

                return jpegData;
            }

            private static bool IsValidJPEG(byte[] data)
            {
                if (data == null || data.Length < 4)
                    return false;

                // Kontrollera JPEG signatur och slutmarkör
                if (data[0] != 0xFF || data[1] != 0xD8)
                    return false;

                // Sök efter JPEG slutmarkör
                for (int i = data.Length - 2; i >= 0; i--)
                {
                    if (data[i] == 0xFF && data[i + 1] == 0xD9)
                        return true;
                }

                return false;
            }

            private static async Task<string> AutoSaveImage(FaceImageInfo faceInfo, string fileName)
            {
                try
                {
                    // Bygg filnamn
                    string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                    string fullFileName = $"{fileName}_{timestamp}.jpg";

                    // Använd MediaStore för att spara bilden
                    var context = global::Android.App.Application.Context;
                    var resolver = context.ContentResolver;

                    ContentValues values = new ContentValues();
                    values.Put(IMediaColumns.DisplayName, fullFileName);
                    values.Put(IMediaColumns.MimeType, "image/jpeg");
                    values.Put(IMediaColumns.RelativePath, DirectoryPictures);

                    var imageUri = resolver.Insert(Images.Media.ExternalContentUri, values);

                    if (imageUri == null)
                    {
                        throw new Exception("Kunde inte skapa URI för att spara bilden.");
                    }

                    using (var outputStream = resolver.OpenOutputStream(imageUri))
                    {
                        if (outputStream == null)
                        {
                            throw new Exception("Kunde inte öppna OutputStream för att spara bilden.");
                        }

                        await outputStream.WriteAsync(faceInfo.ImageData, 0, faceInfo.ImageData.Length);
                    }

                    Console.WriteLine($"Bilden sparades: {imageUri.Path}");
                    return imageUri.Path ?? "Okänd sökväg";
                }
                catch (Exception ex)
                {
                    throw new Exception("Kunde inte spara bilden: " + ex.Message, ex);
                }
            }
        }

        //Funkar bra
        public class MRZParser
        {
            public class MRZData
            {
                public string DocumentType { get; set; }
                public string IssuingCountry { get; set; }
                public string Surname { get; set; }
                public string GivenNames { get; set; }
                public string PassportNumber { get; set; }
                public char PassportNumberCheckDigit { get; set; }
                public string Nationality { get; set; }
                public string BirthDate { get; set; }
                public char BirthDateCheckDigit { get; set; }
                public string Gender { get; set; }
                public string ExpiryDate { get; set; }
                public char ExpiryDateCheckDigit { get; set; }
                public string PersonalNumber { get; set; }
                public char PersonalNumberCheckDigit { get; set; }
                public char FinalCheckDigit { get; set; }

                // Formaterade datum
                public DateTime? ParsedBirthDate => ParseDate(BirthDate);
                public DateTime? ParsedExpiryDate => ParseDate(ExpiryDate);
            }

            public static MRZData ParseMRZ(string cleanMRZ)
            {


                // Dela upp MRZ i rader
                string[] lines = cleanMRZ.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                if (lines.Length < 2)
                    throw new InvalidOperationException("MRZ måste innehålla minst två rader.");

                // Säkerställ att raderna har rätt längd
                string line1 = lines[0].PadRight(44, '<');
                string line2 = lines[1].PadRight(44, '<');

                // Hantera namn
                string fullNamePart = line1.Substring(5);
                string[] nameParts = fullNamePart.Split(new[] { "<<" }, StringSplitOptions.None);
                string surname = nameParts[0].Replace("<", "").Trim();
                string givenNames = nameParts.Length > 1 ? nameParts[1].Replace("<", "").Trim() : "";

                var mrzData = new MRZData
                {
                    DocumentType = line1.Substring(0, 2).Replace("<", "").Trim(),
                    IssuingCountry = line1.Substring(2, 3).Trim(),
                    Surname = surname,
                    GivenNames = givenNames,
                    PassportNumber = line2.Substring(0, 9).Replace("<", "").Trim(),
                    PassportNumberCheckDigit = line2[9],
                    Nationality = line2.Substring(10, 3).Trim(),
                    BirthDate = line2.Substring(13, 6).Trim(),
                    BirthDateCheckDigit = line2[19],
                    Gender = line2.Substring(20, 1).Trim(),
                    ExpiryDate = line2.Substring(21, 6).Trim(),
                    ExpiryDateCheckDigit = line2[27],
                    PersonalNumber = line2.Substring(28, 14).Replace("<", "").Trim(),
                    PersonalNumberCheckDigit = line2[42],
                    FinalCheckDigit = line2[43]
                };

                return mrzData;
            }

            private static DateTime? ParseDate(string date)
            {
                if (string.IsNullOrEmpty(date) || date.Length != 6)
                    return null;

                try
                {
                    int year = int.Parse(date.Substring(0, 2));
                    int month = int.Parse(date.Substring(2, 2));
                    int day = int.Parse(date.Substring(4, 2));

                    // Hantera århundrade (19xx eller 20xx)
                    int fullYear = year + (year >= 50 ? 1900 : 2000);

                    return new DateTime(fullYear, month, day);
                }
                catch
                {
                    return null;
                }
            }

            // Hjälpmetod för att få data som Dictionary
            public static Dictionary<string, string> ToDictionary(MRZData data)
            {
                return new Dictionary<string, string>
        {
            { "Document Type", data.DocumentType },
            { "Issuing Country", data.IssuingCountry },
            { "Surname", data.Surname },
            { "Given Names", data.GivenNames },
            { "Full Name", $"{data.Surname} {data.GivenNames}".Trim() },
            { "Passport Number", data.PassportNumber },
            { "Passport Number Check Digit", data.PassportNumberCheckDigit.ToString() },
            { "Nationality", data.Nationality },
            { "Birth Date", data.BirthDate },
            { "Birth Date Formatted", data.ParsedBirthDate?.ToString("yyyy-MM-dd") ?? "" },
            { "Birth Date Check Digit", data.BirthDateCheckDigit.ToString() },
            { "Gender", data.Gender },
            { "Expiry Date", data.ExpiryDate },
            { "Expiry Date Formatted", data.ParsedExpiryDate?.ToString("yyyy-MM-dd") ?? "" },
            { "Expiry Date Check Digit", data.ExpiryDateCheckDigit.ToString() },
            { "Personal Number", data.PersonalNumber },
            { "Personal Number Check Digit", data.PersonalNumberCheckDigit.ToString() },
            { "Final Check Digit", data.FinalCheckDigit.ToString() }
        };
            }
        }

        private static Dictionary<string, string> ParseMRZ(string cleanMRZ)
        {
            // Dela upp MRZ i rader
            string[] lines = cleanMRZ.Split('\n');
            if (lines.Length < 2) throw new InvalidOperationException("MRZ måste innehålla minst två rader.");

            // Extrahera data från första raden
            string line1 = lines[0].PadRight(44); // Säkerställ att raden har 44 tecken
            string documentType = line1.Substring(0, 1).Trim();
            string issuingCountry = line1.Substring(2, 3).Trim();
            string fullName = line1.Substring(5).Replace("<<", " ").Trim();

            // Extrahera data från andra raden
            string line2 = lines[1].PadRight(44); // Säkerställ att raden har 44 tecken
            string passportNumber = line2.Substring(0, 9).Trim();
            char passportNumberCheckDigit = line2[9];
            string nationality = line2.Substring(10, 3).Trim();
            string birthDate = line2.Substring(13, 6).Trim();
            char birthDateCheckDigit = line2[19];
            string gender = line2.Substring(20, 1).Trim();
            string expiryDate = line2.Substring(21, 6).Trim();
            char expiryDateCheckDigit = line2[27];
            string personalNumber = line2.Substring(28, 14).Trim();
            char personalNumberCheckDigit = line2[42];
            char finalCheckDigit = line2[43];

            // Returnera parsad information
            return new Dictionary<string, string>
            {
                { "Document Type", documentType },
                { "Issuing Country", issuingCountry },
                { "Full Name", fullName },
                { "Passport Number", passportNumber },
                { "Passport Number Check Digit", passportNumberCheckDigit.ToString() },
                { "Nationality", nationality },
                { "Birth Date", birthDate },
                { "Birth Date Check Digit", birthDateCheckDigit.ToString() },
                { "Gender", gender },
                { "Expiry Date", expiryDate },
                { "Expiry Date Check Digit", expiryDateCheckDigit.ToString() },
                { "Personal Number", personalNumber },
                { "Personal Number Check Digit", personalNumberCheckDigit.ToString() },
                { "Final Check Digit", finalCheckDigit.ToString() }
            };
        }

        //Funkar bra
        public class MRZByteParser
        {
            public static string ParseMRZBytes(byte[] bytes)
            {
                if (bytes == null || bytes.Length == 0)
                    return string.Empty;

                StringBuilder mrz = new StringBuilder();
                bool startedReading = false;

                for (int i = 0; i < bytes.Length; i++)
                {
                    byte b = bytes[i];

                    // Börja läsa efter vi hittar 'P' eller '<'
                    if (!startedReading && (b == 0x50 || b == 0x3C))
                    {
                        startedReading = true;
                    }

                    if (startedReading)
                    {
                        // Inkludera bara giltiga MRZ-tecken
                        if ((b >= 0x30 && b <= 0x39) ||  // Siffror
                            (b >= 0x41 && b <= 0x5A) ||  // Stora bokstäver
                            b == 0x3C)                   // < tecken
                        {
                            mrz.Append((char)b);
                        }
                    }
                }

                string result = mrz.ToString();

                // Säkerställ att resultatet har korrekt längd för MRZ (44 tecken per rad)
                if (result.Length >= 88)
                {
                    return result.Substring(0, 88);
                }

                // Fyll ut med < tecken om det behövs
                return result.PadRight(88, '<');
            }

            public static string FormatMRZForBAC(string mrz)
            {
                // Säkerställ att vi har exakt två rader med 44 tecken var
                string[] lines = new string[2];

                if (mrz.Length >= 44)
                {
                    lines[0] = mrz.Substring(0, 44);
                    lines[1] = mrz.Length >= 88 ? mrz.Substring(44, 44) : mrz.Substring(44).PadRight(44, '<');
                }
                else
                {
                    lines[0] = mrz.PadRight(44, '<');
                    lines[1] = "".PadRight(44, '<');
                }

                return lines[0] + "\n" + lines[1];
            }

            public static (string DocumentNumber, string DateOfBirth, string DateOfExpiry) ExtractBACElements(string mrz)
            {
                // Extrahera relevanta delar för BAC
                string documentNumber = "";
                string dateOfBirth = "";
                string dateOfExpiry = "";

                try
                {
                    // Dokumentnummer finns vanligtvis i andra raden
                    string[] lines = mrz.Split('\n');
                    if (lines.Length >= 2)
                    {
                        documentNumber = lines[1].Substring(0, 9).Trim('<');
                        dateOfBirth = lines[1].Substring(13, 6);
                        dateOfExpiry = lines[1].Substring(21, 6);
                    }
                }
                catch
                {
                    // Vid fel, returnera tomma strängar
                }

                return (documentNumber, dateOfBirth, dateOfExpiry);
            }
        }
        public static void VerifyRapduCC(byte[] rapdu, ref byte[] ssc, byte[] ksMac, byte[] ksEnc)
        {
            Console.WriteLine($"rapdu: {BitConverter.ToString(rapdu)}");


            //-----------------------------------------------------------------------ii. Concatenate SSC, DO‘87’ and DO‘99’ and add padding: -extract DO‘87’ and DO‘99’ from RPADU-
            //                                                                          K = ‘88-70-22-12-0C-06-C2-2C-87-19-01-FB-92-35-F4-E4-03-7F-23-27-DC-C8-96-4F-1F-9B-8C-30-F4-2C-8E-2F-FF-22-4A-99-02-90-00’ - Rätt
            //                                                                     Recieved: 88-70-22-12-0C-06-C2-2C-87-19-01-FB-92-35-F4-E4-03-7F-23-27-DC-C8-96-4F-1F-9B-8C-30-F4-2C-8E-2F-FF-22-4A-99-02-90-00
            // 1. Extract DO87 and DO99 from RAPDU
            byte[] do87 = ExtractDO87(rapdu);
            byte[] do99 = ExtractDO99(rapdu);

            Console.WriteLine($"ksMac: {BitConverter.ToString(ksMac)}");
            Console.WriteLine($"DO87: {BitConverter.ToString(do87)}");
            Console.WriteLine($"DO99: {BitConverter.ToString(do99)}");
            Console.WriteLine($"SSC: {BitConverter.ToString(ssc)}");


            // 2. build K SSC, DO‘87’ and DO‘99’ and add padding
            byte[] concatenatedData = ssc.Concat(do87).Concat(do99).ToArray();
            byte[] paddedData = PadIso9797Method2(concatenatedData);

            Console.WriteLine($"Concatenated (SSC + DO87 + DO99): {BitConverter.ToString(concatenatedData)}");
            Console.WriteLine($"Padded Data: {BitConverter.ToString(paddedData)}");

            //-----------------------------------------------------------------------iii. Compute MAC with KSMAC: CC’ = ‘C8-B2-78-7E-AE-A0-7D-74’ - C8-B2-78-7E-AE-A0-7D-74 - Rätt
            byte[] calculatedMacCC = ComputeMac3DES2(concatenatedData, ksMac);
            Console.WriteLine($"Calculated MAC -(CC)-: {BitConverter.ToString(calculatedMacCC)}");

            //-----------------------------------------------------------------------iv. Compare CC’ with data of DO‘8E’ of RAPDU ‘C8-B2-78-7E-AE-A0-7D-74’ == ‘C8-B2-78-7E-AE-A0-7D-74’ ? YES. - Rätt
            // 1. Extract DO8E from RAPDU
            byte[] do8e = ExtractDO8E2(rapdu);
            Console.WriteLine($"do8e from RAPDU: {BitConverter.ToString(do8e)}");

            // 2. Extract CC from DO8E in RAPDU
            byte[] ccFromRapdu = do8e.Skip(2).Take(8).ToArray();
            Console.WriteLine($"CC from RAPDU: {BitConverter.ToString(ccFromRapdu)}");

            // 3. Compare CC’ with data of DO‘8E’
            if (calculatedMacCC.SequenceEqual(ccFromRapdu))
            {
                Console.WriteLine("CC verified successfully! MAC matches CC from RAPDU.");
            }
            else
            {
                Console.WriteLine("CC verification failed. Calculated MAC does not match CC from RAPDU.");
            }


            //-----------------------------------------------------------------------iVV. Decrypt data of DO‘87’ with KSEnc: DecryptedData = ‘04-30-31-30-36-5F-36-06-30-34-30-30-30-30-5C-02-61-75’
            //                                                                                                                      Recieved: 04-30-31-30-36-5F-36-06-30-34-30-30-30-30-5C-02-61-75
            byte[] DecryptedData = DecryptDO87WithKSEnc(do87, ksEnc);
            byte[] efComData = BuildEfComData(DecryptedData);
            Console.WriteLine($"DecryptedData no padding: {BitConverter.ToString(DecryptedData)}");
            //Console.WriteLine($"EF.COM data: {BitConverter.ToString(efComData)}");
            byte lengthField = DecryptedData[1];
            int L = lengthField + 2;
            Console.WriteLine($"Determined length (L): {L} bytes");



            //var efData = ParseEFComData(efComData);

            //ParseEfComData(efComData);
            //DG1Parser.ParseAndPresentDG1(DecryptedData);
        }
        public class DG1Parser
        {
            public static void ParseAndPresentDG1(byte[] data)
            {
                try
                {
                    // Konvertera bytes till string
                    string mrzData = Encoding.ASCII.GetString(data);

                    // Rensa bort eventuella null-bytes och trimma
                    mrzData = new string(mrzData.Where(c => c != '\0').ToArray()).Trim();

                    Console.WriteLine("\n=== Passport Data (DG1) ===\n");

                    // Hantera '<' specialtecken och dela upp namnen
                    string[] nameParts = mrzData.Split(new[] { "<<" }, StringSplitOptions.None);

                    // Extrahera landkod (de första tre tecknen efter P eller I)
                    string documentType = mrzData.Substring(0, 1);
                    string countryCode = mrzData.Substring(1, 3);

                    // Extrahera och formatera namn
                    string surname = nameParts[0].Substring(4).Replace("<", " ").Trim();
                    string givenNames = nameParts.Length > 1 ? nameParts[1].Replace("<", " ").Trim() : "";

                    // Presentera datan på ett snyggt sätt
                    Console.WriteLine($"Document Type: {(documentType == "P" ? "Passport" : documentType)}");
                    Console.WriteLine($"Country Code: {countryCode}");
                    Console.WriteLine($"Surname: {surname}");
                    Console.WriteLine($"Given Names: {givenNames}");

                    // Visa även rådatan för verifiering
                    Console.WriteLine("\nRaw MRZ Data:");
                    Console.WriteLine(mrzData);

                    // Visa hexadecimal representation
                    Console.WriteLine("\nHexadecimal representation:");
                    Console.WriteLine(BitConverter.ToString(data));
                    Console.WriteLine($"Raw data:{data}");

                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error parsing DG1 data: {ex.Message}");
                    Console.WriteLine("Raw data:");
                    Console.WriteLine(BitConverter.ToString(data));
                }
            }

            // Hjälpmetod för att konvertera MRZ-datum till läsbart format
            private static string FormatMRZDate(string mrzDate)
            {
                if (mrzDate.Length != 6) return mrzDate;

                try
                {
                    int year = int.Parse(mrzDate.Substring(0, 2));
                    int month = int.Parse(mrzDate.Substring(2, 2));
                    int day = int.Parse(mrzDate.Substring(4, 2));

                    // Antag att år 00-99 är 1900-1999
                    if (year < 50) year += 2000;
                    else year += 1900;

                    return $"{year:D4}-{month:D2}-{day:D2}";
                }
                catch
                {
                    return mrzDate;
                }
            }

            // Hjälpmetod för att validera checksiffror
            private static bool ValidateCheckDigit(string data, int checkDigitPosition)
            {
                if (checkDigitPosition >= data.Length) return false;

                int sum = 0;
                int[] weights = { 7, 3, 1 };
                int weightIndex = 0;

                for (int i = 0; i < checkDigitPosition; i++)
                {
                    char c = data[i];
                    int value;

                    if (char.IsDigit(c))
                        value = c - '0';
                    else if (c == '<')
                        value = 0;
                    else
                        value = c - 'A' + 10;

                    sum += value * weights[weightIndex];
                    weightIndex = (weightIndex + 1) % 3;
                }

                int checkDigit = sum % 10;
                return checkDigit.ToString()[0] == data[checkDigitPosition];
            }
        }


        //Funkar bra
        public static List<byte[]> ReadCompleteDG(IsoDep isoDep, byte[] KSEnc, byte[] KSMac, ref byte[] SSC)
        {
            try
            {
                List<byte[]> fullData = new List<byte[]>();
                int offset = 0;
                const int blockSize = 0x20; // Standardstorlek för block i MRTD-kommunikation (32 bytes)

                while (true)
                {
                    Console.WriteLine($"Reading DG1 at offset: {offset}");

                    // Steg 1: Bygg READ BINARY-kommando för nuvarande offset
                    byte[] cmdHeader = { 0x0C, 0xB0, (byte)(offset >> 8), (byte)(offset & 0xFF), 0x80, 0x00, 0x00, 0x00 };
                    byte[] DO97 = { 0x97, 0x01, (byte)blockSize };
                    byte[] M = cmdHeader.Concat(DO97).ToArray();

                    IncrementSSC(ref SSC);

                    byte[] NNoPad = SSC.Concat(M).ToArray();
                    byte[] N = PadIso9797Method2(NNoPad);

                    byte[] CC = ComputeMac3DES(NNoPad, KSMac);
                    byte[] DO8E = BuildDO8E(CC);
                    byte[] protectedAPDU = ConstructProtectedAPDU(cmdHeader, DO97, DO8E);

                    Console.WriteLine($"Sending Protected APDU: {BitConverter.ToString(protectedAPDU)}");

                    // Steg 2: Skicka kommando till DG1
                    byte[] RAPDU = isoDep.Transceive(protectedAPDU);

                    if (RAPDU.Length < 2 || RAPDU[^2] != 0x90 || RAPDU[^1] != 0x00)
                    {
                        Console.WriteLine($"Error reading DG: {BitConverter.ToString(RAPDU)}");
                        break;
                    }
                    // Steg 3: Kontrollera svar och verifiera CC
                    IncrementSSC(ref SSC);
                    VerifyRapduCC(RAPDU, ref SSC, KSMac, KSEnc);

                    // Extrahera och dekryptera data från RAPDU
                    byte[] do87 = ExtractDO87(RAPDU);
                    byte[] encryptedData = ExtractEncryptedDataFromDO87(do87);
                    byte[] decryptedData = DecryptWithKEnc3DES(encryptedData, KSEnc);

                    // Lägg till dekrypterad data till fullData
                    fullData.AddRange(decryptedData);
                    Console.WriteLine($"Decrypted Data added: {BitConverter.ToString(decryptedData)}");

                    Console.WriteLine($"Decrypted Data (Offset {offset}): {BitConverter.ToString(decryptedData)}");

                    // Kontrollera om sista segmentet lästs
                    if (decryptedData.Length < 0x20) // Mindre än maximalt möjligt per segment
                    {
                        Console.WriteLine("End of DG reached.");
                        break;
                    }

                    // Uppdatera offset för nästa block
                    offset += 0x20;
                }

                // Returnera all kombinerad data
                return fullData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading DG1: {ex.Message}");
                return null;
            }
        }


        private static byte[] BuildEfComData(byte[] decryptedData)
        {
            // Header för EF.COM data
            byte[] header = { 0x60, 0x14, 0x5F, 0x01 };

            // Kombinera header och avkodad data
            return header.Concat(decryptedData).ToArray();
        }

        private static byte[] ComputeMac3DES2(byte[] data, byte[] ksMac)
        {
            if (ksMac.Length != 16 && ksMac.Length != 24)
                throw new ArgumentException("Key length must be 16 or 24 bytes for 3DES.");

            // Dela upp nyckeln
            byte[] key1 = ksMac.Take(8).ToArray();
            byte[] key2 = ksMac.Skip(8).Take(8).ToArray();

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

                // Lägg till padding
                byte[] paddedData = PadIso9797Method2(data);

                // MAC steg 1: Kryptera
                byte[] intermediate = des1.CreateEncryptor().TransformFinalBlock(paddedData, 0, paddedData.Length);

                // MAC steg 2: Dekryptera
                byte[] decrypted = des2.CreateDecryptor().TransformFinalBlock(intermediate, intermediate.Length - 8, 8);

                // MAC steg 3: Kryptera igen
                return des1.CreateEncryptor().TransformFinalBlock(decrypted, 0, 8);
            }
        }

        private static byte[] ExtractDO8E2(byte[] rapdu)
        {
            // DO8E startar med taggen 0x8E
            int index = Array.IndexOf(rapdu, (byte)0x8E);
            if (index == -1) throw new InvalidOperationException("DO8E not found in RAPDU.");

            int length = rapdu[index + 1]; // DO8E längd
            return rapdu.Skip(index).Take(2 + length).ToArray(); // Tag + Längd + Data
        }

        private static byte[] ExtractDO87(byte[] rapdu)
        {
            // DO87 startar med taggen 0x87
            int index = Array.IndexOf(rapdu, (byte)0x87);
            if (index == -1) throw new InvalidOperationException("DO87 not found in RAPDU.");

            int length = rapdu[index + 1]; // DO87 längd
            return rapdu.Skip(index).Take(2 + length).ToArray(); // Tag + Längd + Data
        }

        private static byte[] ExtractDO99(byte[] rapdu)
        {
            // DO99 startar med taggen 0x99
            int index = Array.IndexOf(rapdu, (byte)0x99);
            if (index == -1) throw new InvalidOperationException("DO99 not found in RAPDU.");

            return rapdu.Skip(index).Take(4).ToArray(); // Tag (0x99) + 2 bytes data + 2 bytes SW
        }

        private static byte[] DecryptDO87WithKSEnc(byte[] do87, byte[] ksEnc)
        {
            // Kontrollera att DO87 är korrekt strukturerad
            if (do87[0] != 0x87) throw new InvalidOperationException("Invalid DO87 structure. Missing 0x87 tag.");

            // Extrahera den krypterade datan från DO87
            int dataLength = do87[1] - 1; // Minska 1 för indikator (0x01)
            if (dataLength <= 0 || dataLength + 2 > do87.Length)
                throw new InvalidOperationException("Invalid DO87 data length.");

            byte[] encryptedData = do87.Skip(3).Take(dataLength).ToArray();
            Console.WriteLine($"Encrypted Data: {BitConverter.ToString(encryptedData)}");

            // Dekryptera med KSEnc
            using (var tripleDes = TripleDES.Create())
            {
                tripleDes.Key = ksEnc;
                tripleDes.Mode = CipherMode.CBC;
                tripleDes.Padding = PaddingMode.None;
                tripleDes.IV = new byte[8]; // IV = 8 nollbytes

                using (var decryptor = tripleDes.CreateDecryptor())
                {
                    byte[] decryptedData = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                    Console.WriteLine($"Decrypted Data with padding: {BitConverter.ToString(decryptedData)}");

                    // Returnera utan padding
                    return RemovePadding(decryptedData);
                }
            }
        }

        private static byte[] RemovePadding(byte[] data)
        {
            int unpaddedLength = data.Length;
            while (unpaddedLength > 0 && data[unpaddedLength - 1] == 0x00)
            {
                unpaddedLength--;
            }

            // Kontrollera ISO-9797-1 Padding Metod 2 (sista byte ska vara 0x80)
            if (unpaddedLength > 0 && data[unpaddedLength - 1] == 0x80)
            {
                unpaddedLength--;
            }

            return data.Take(unpaddedLength).ToArray();
        }


        private static byte[] EncryptWithKEnc3DES(byte[] data, byte[] KEnc)
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

        private static byte[] DecryptWithKEnc3DES(byte[] data, byte[] KEnc)
        {
            using (var tripleDes = TripleDES.Create())
            {
                tripleDes.Key = KEnc;               // 3DES-nyckel (24 bytes)
                tripleDes.Mode = CipherMode.CBC;
                tripleDes.Padding = PaddingMode.None;
                tripleDes.IV = new byte[8];         // IV = 8 nollbytes


                var decryptedData = tripleDes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);

                return decryptedData;
            }
        }

        private static byte[] CheckRndIfd(byte[] decryptedR, byte[] rndIfd)
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

        static byte[] ComputeKSeed(byte[] kIfd, byte[] kIc)
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

        static byte[] ComputeSSC(byte[] rndIc2, byte[] rndIfd2)
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

        static byte[] BuildDO87(byte[] encryptedData)
        {
            byte[] DO87 = new byte[1 + 1 + 1 + encryptedData.Length];
            DO87[0] = 0x87; // Tag för DO87
            DO87[1] = (byte)(1 + encryptedData.Length); // Längd
            DO87[2] = 0x01; // Indikator för krypterat data
            Array.Copy(encryptedData, 0, DO87, 3, encryptedData.Length);
            return DO87;
        }

        private static void IncrementSSC(ref byte[] SSC)
        {
            for (int i = SSC.Length - 1; i >= 0; i--)
            {
                if (++SSC[i] != 0) break;
            }
        }

        private static byte[] BuildDO8E(byte[] mac)
        {
            if (mac.Length != 8)
                throw new ArgumentException("MAC length must be 8 bytes.");

            // Tag '8E'
            byte tag = 0x8E;

            // Length of MAC (always 8 bytes)
            byte length = 0x08;

            // Bygg DO '8E'
            byte[] do8e = new byte[2 + mac.Length];
            do8e[0] = tag;           // Tag
            do8e[1] = length;        // Length
            Array.Copy(mac, 0, do8e, 2, mac.Length); // Value (MAC)

            return do8e;
        }

        static byte[] ConstructProtectedAPDU(byte[] cmdHeader, byte[] DO87, byte[] DO8E)
        {
            // Lc = Length of DO87 + DO8E
            byte[] shortCmdHeader = cmdHeader.Take(4).ToArray();
            byte lc = (byte)(DO87.Length + DO8E.Length);

            // Bygg Protected APDU
            byte[] protectedAPDU = new byte[shortCmdHeader.Length + 1 + DO87.Length + DO8E.Length + 1];
            Array.Copy(shortCmdHeader, 0, protectedAPDU, 0, shortCmdHeader.Length); // Kopiera CmdHeader
            protectedAPDU[shortCmdHeader.Length] = lc;                        // Lägg till Lc
            Array.Copy(DO87, 0, protectedAPDU, shortCmdHeader.Length + 1, DO87.Length); // Lägg till DO87
            Array.Copy(DO8E, 0, protectedAPDU, shortCmdHeader.Length + 1 + DO87.Length, DO8E.Length); // Lägg till DO8E
            protectedAPDU[^1] = 0x00;                                   // Lägg till Le (0x00)

            return protectedAPDU;
        }

        static byte[] ExtractDO8E(byte[] rapdu)
        {
            int index = Array.IndexOf(rapdu, (byte)0x8E);
            if (index != -1 && index + 1 < rapdu.Length)
            {
                int length = rapdu[index + 1];
                byte[] do8e = new byte[length];
                Array.Copy(rapdu, index + 2, do8e, 0, length);
                Console.WriteLine($"DO‘8E’: {BitConverter.ToString(do8e)}");

                return do8e;
            }
            else
            {
                Console.WriteLine("DO‘8E’ wasnt found in RAPDU.");
                return null;
            }
        }

        static byte[] ExtractEncryptedDataFromDO87(byte[] DO87)
        {
            if (DO87[0] != 0x87)
                throw new ArgumentException("Invalid DO‘87’ format");

            int length = DO87[1];
            if (DO87[2] != 0x01) // Förväntar indikator för krypterat data
                throw new ArgumentException("Invalid encrypted data indicator");

            byte[] encryptedData = new byte[length - 1];
            Array.Copy(DO87, 3, encryptedData, 0, encryptedData.Length);
            return encryptedData;
        }

        private static bool IsSuccessfulResponse(byte[] response)
        {
            return response.Length >= 2 && response[^2] == 0x90 && response[^1] == 0x00;
        }

    }
}
