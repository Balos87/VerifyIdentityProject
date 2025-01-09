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
                byte[] eIc = apduResponse.Take(32).ToArray();
                byte[] mIc = apduResponse.Skip(32).Take(8).ToArray();
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

                //--------------------------------------------------------------------  D.4 SECURE MESSAGING

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
                    0x01, 0x01,  // File ID för EF.COM
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
                byte[] CC = ComputeMac3DES(NNopad, kSMac); //use with no pad so compute can work!
                Console.WriteLine($"-N Nopad-: {BitConverter.ToString(NNopad)}");
                Console.WriteLine($"-CC- (MAC over N with KSMAC): {BitConverter.ToString(CC)}");


                //--------------------------------------------------------------------  3. Build DO‘8E’ - 8E-08-BF-8B-92-D6-35-FF-24-F8 - Recieved: 8E-08-BF-8B-92-D6-35-FF-24-F8 -- RÄTT
                byte[] DO8E = BuildDO8E(CC);
                Console.WriteLine($"DO8E: {BitConverter.ToString(DO8E)}");


                //--------------------------------------------------------------------  3. Construct & send protected APDU: ProtectedAPDU = ‘0C-A4-02-0C-15-87-09-01-63-75-43-29-08-C0-44-F6-8E-08-BF-8B-92-D6-35-FF-24-F8-00’--RÄTT
                //                                                                                                                 Recieved: 0C-A4-02-0C-15-87-09-01-63-75-43-29-08-C0-44-F6-8E-08-BF-8B-92-D6-35-FF-24-F8-00 
                byte[] protectedAPDU = ConstructProtectedAPDU(cmdHeader,DO87, DO8E);
                Console.WriteLine($"Protected APDU: {BitConverter.ToString(protectedAPDU)}");

                //---------------------------------------------------------------------- Send and  Receive response APDU of eMRTD’s contactless IC: RAPDU = ‘99-02-90-00-8E-08-FA-85-5A-5D-4C-50-A8-ED-90-00’ ?- RÄTT
                //                                                                                                 Dummy data wont work here since it gets 69-88. But works with my passport
                byte[] RAPDU = isoDep.Transceive(protectedAPDU);
                Console.WriteLine($"APDU Response: {BitConverter.ToString(RAPDU)}");

                byte[] RAPDU2 = { 0x99 ,0x02 ,0x90 ,0x00 ,0x8E ,0x08 ,0xFA ,0x85 ,0x5A ,0x5D ,0x4C ,0x50 ,0xA8 ,0xED ,0x90 ,0x00 }; // - Dummy/test data
                Console.WriteLine($"APDU2 Response: {BitConverter.ToString(RAPDU2)}");

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
                if ( isEqual )
                Console.WriteLine($"CC' == DO‘8E’: {isEqual}");
                Console.WriteLine($"extracted DO8E: {BitConverter.ToString(extractedDO8E)} = CC: {BitConverter.ToString(ccMac)}");




                //----------------------------------------------------------------------- 1 Read Binary of first four bytes
                Console.WriteLine("/----------------------------------------------------------------------- 1 Read Binary of first four bytes");
                List<byte[]> dg1Segments = ReadCompleteDG1(isoDep, KSEncParitet, KSMacParitet, ref SSC);
                if (dg1Segments.Count > 0)
                {
                    byte[] completeDG1 = dg1Segments.SelectMany(segment => segment).ToArray();
                    Console.WriteLine($"Complete DG1 Data: {BitConverter.ToString(completeDG1)}");



                    Console.WriteLine($"Parsed nya");
                    var text = MRZByteParser.ParseMRZBytes(completeDG1);
                    var klar = MRZByteParser.FormatMRZForBAC(text);
                    Console.WriteLine($"text {text}");
                    Console.WriteLine($"klar {klar}");

                    var hel = MRZParser.ParseMRZ(klar);
                    
                    var dic = MRZParser.ToDictionary(hel);

                    var parsedMRZ = ParseMRZ(klar);

                    foreach (var field in dic)
                    {
                        Console.WriteLine($"{field.Key}: {field.Value}");
                    }

                    var bildbit = DG2Parser.ParseDG2(completeDG1);
                    Console.WriteLine($"--------------dg2 {bildbit}");

                }
                else
                {
                    Console.WriteLine("Failed to read DG1.");
                }

                //----------------------------------------------------------------------- 1.1 CmdHeader = ‘0C-B0-00-00-80-00-00-00’Read Binary of first four bytes -- RÄTT
                byte[] rBCmdHeader = new byte[]
                {
                    0x0C, 0xB0, 0x00, 0x00, // CLA, INS, P1, P2
                    0x80, 0x00, 0x00, 0x00  // Padding (Mask) 
                };
                Console.WriteLine($"CmdHeader (Read Binary): {BitConverter.ToString(rBCmdHeader)}");

                //----------------------------------------------------------------------- 1.2 Build DO‘97’: DO97 = ‘97-01-04’  -- RÄTT
                byte[] DO97 = new byte[] { 0x97, 0x01, 0x04 };
                Console.WriteLine($"DO97 (Read Binary): {BitConverter.ToString(DO97)}");

                //----------------------------------------------------------------------- 1.3 Concatenate CmdHeader and DO‘97’: M = ‘0C-B0-00-00-80-00-00-00-97-01-04 - Recieved: 0C-B0-00-04-80-00-00-00-97-01-04 -- RÄTT
                byte[] rbM = rBCmdHeader.Concat(DO97).ToArray();
                Console.WriteLine($"M (Read Binary): {BitConverter.ToString(rbM)}");

                //----------------------------------------------------------------------- 1.4 Compute MAC of M:

                //----------------------------------------------------------------------- 1.4.1 Increment SSC with 1: SSC = ‘88-70-22-12-0C-06-C2-29’ - Recieved: 88-70-22-12-0C-06-C2-29 -- RÄTT
                IncrementSSC(ref SSC);
                Console.WriteLine($"Incremented SSC (Read Binary): {BitConverter.ToString(SSC)}");

                //----------------------------------------------------------------------- 1.4.2 Concatenate SSC and M and add padding: N = ‘88-70-22-12-0C-06-C2-29-0C-B0-00-00-80-00-00-00-97-01-04-80-00-00-00-00 -- RÄTT
                //                                                                                                                Recieved: 88-70-22-12-0C-06-C2-29-0C-B0-00-00-80-00-00-00-97-01-04-80-00-00-00-00
                byte[] rbN = PadIso9797Method2(SSC.Concat(rbM).ToArray());
                Console.WriteLine($"N - (Read Binary) Padded-data : {BitConverter.ToString(rbN)}");

                //----------------------------------------------------------------------- 1.4.3 Compute MAC over N with KSMAC CC = ‘ED-67-05-41-7E-96-BA-55’ - Recieved: ED-67-05-41-7E-96-BA-55 -- RÄTT
                byte[] nNoPad = SSC.Concat(rbM).ToArray(); //removed pad so compute can work!
                byte[] nCC = ComputeMac3DES(nNoPad, KSMacParitet);
                Console.WriteLine($"CC (Read Binary) Computed MAC: {BitConverter.ToString(nCC)}");

                //----------------------------------------------------------------------- 1.5 Build DO‘8E’: DO8E = ‘8E-08-ED-67-05-41-7E-96-BA-55' - Recieved: 8E-08-ED-67-05-41-7E-96-BA-55’ -- RÄTT
                byte[] DO8Erb = BuildDO8E(nCC);
                Console.WriteLine($"DO8E (Read Binary): {BitConverter.ToString(DO8Erb)}");

                //----------------------------------------------------------------------- 1.6 Construct and send protected APDU: ProtectedAPDU = ‘0C-B0-00-00-0D-97-01-04-8E-08-ED-67-05-41-7E-96-BA-55-00’ - RÄTT
                //                                                                           (cmdheader)0CB00000+0D+do97+do8e+cc        Recieved: 0C-B0-00-00-0D-97-01-04-8E-08-ED-67-05-41-7E-96-BA-55-00
                byte[] protectedAPDURb = ConstructProtectedAPDU(rBCmdHeader, DO97, DO8Erb);
                Console.WriteLine($"Protected APDU (Read Binary): {BitConverter.ToString(protectedAPDURb)}");

                //------------------------------------------------------ 1.7 Send and Receive response APDU of eMRTD’s contactless IC: RAPDU = 87-09-01-9F-F0-EC-34-F9-92-26-51-99-02-90-00-8E-08-AD-55-CC-17-14-0B-2D-ED-90-00
                //                                                                                                APDU Response (Read Binary): 68-82. But with real pass data it gives correct answer          ?- RÄTT
                byte[] RAPDUrb = isoDep.Transceive(protectedAPDURb);
                Console.WriteLine($"APDU Response (Read Binary): {BitConverter.ToString(RAPDUrb)}");



                //----------------------------------------------------------------------- 1. Verify RAPDU CC by computing MAC of concatenation DO‘87’ and DO‘99’:

                //----------------------------------------------------------------------- 1.2 Increment SSC with 1: SSC = ‘88-70-22-12-0C-06-C2-2A’ - Recieved: 88-70-22-12-0C-06-C2-2A -- RÄTT
                IncrementSSC(ref SSC);
                Console.WriteLine($"Incremented SSC (Read Binary): {BitConverter.ToString(SSC)}");

                //----------------------------------------------------------------------- 1.3 Concatenate SSC, DO‘87’ and DO‘99’ and add padding: K = ‘88-70-22-12-0C-06-C2-2A-87-09-01-9F-F0-EC-34-F9-92-26-51-99-02-90-00-80’
                //                                                                                                 Dummy data wont work here since (k) is not right. But works with my passport.
                //                                                                                                                           Recieved: 88-70-22-12-0C-06-C2-2A-87-09-01-63-75-43-29-08-C0-44-F6-99-02-90-00-80
                byte[] DO872 = { 0x87, 0x09, 0x01, 0x9F, 0xF0, 0xEC, 0x34, 0xF9, 0x92, 0x26, 0x51 };
                byte[] extractedDO87 = ExtractDO87FromRAPDU(RAPDUrb);
                Console.WriteLine($"Extracted DO87: {BitConverter.ToString(extractedDO87)}");


                byte[] rbK = PadIso9797Method2(SSC.Concat(extractedDO87).Concat(DO99).ToArray());
                Console.WriteLine($"K - (Read Binary) Padded-data: {BitConverter.ToString(rbK)}");

                //----------------------------------------------------------------------- 1.4 Compute MAC with KSMAC: CC’ = ‘AD-55-CC-17-14-0B-2D-ED’ - Recieved: AD-55-CC-17-14-0B-2D-ED -- RÄTT 
                //                                                                                                 Dummy data wont work here since (k) is not right. But works with my passport.
                byte[] rBkNoPad = SSC.Concat(extractedDO87).Concat(DO99).ToArray(); //removed pad so compute can work!
                byte[] rBCC = ComputeMac3DES(rBkNoPad, KSMacParitet);
                Console.WriteLine($"CC (Read Binary) Computed MAC: {BitConverter.ToString(rBCC)}");

                //----------------------------------------------------------------------- 1.5 Compare CC’ with data of DO‘8E’ of RAPDU: ‘AD55CC17140B2DED’ == ‘AD55CC17140B2DED’ ? YES. -- RÄTT
                var rbExtractedDO8E = ExtractDO8E(RAPDUrb);
                bool rBIsEqual = rBCC.SequenceEqual(rbExtractedDO8E);
                if (rBIsEqual)
                    Console.WriteLine($"CC' == DO‘8E’: {rBIsEqual}");
                Console.WriteLine($"extracted DO8E: {BitConverter.ToString(rbExtractedDO8E)} = CC: {BitConverter.ToString(rBCC)}");

                //----------------------------------------------------------------------- 1.6 Decrypt data of DO‘87’ with KSEnc: DecryptedData = ‘60-14-5F-01’ - Recieved: 60-14-5F-01-80-00-00-00 -- Rätt my data: 60-18-5F-01-80-00-00-00
                byte[] KsEncPart = { 0x97 ,0x9E ,0xC1 ,0x3B ,0x1C ,0xBF ,0xE9 ,0xDC ,0xD0 ,0x1A ,0xB0 ,0xFE ,0xD3 ,0x07 ,0xEA ,0xE5 };
                Console.WriteLine($"KsEnc (dummyData): {BitConverter.ToString(KsEncPart)}");

                var encryptDataFromDO87 = ExtractEncryptedDataFromDO87(extractedDO87);
                Console.WriteLine($"Extracted Ecnrypted-data from DO87: {BitConverter.ToString(encryptDataFromDO87)}");

                byte[] rapduDecryptedData = DecryptWithKEnc3DES(encryptDataFromDO87, KSEncParitet); //KSEncParitet
                Console.WriteLine($"Decrypted Data with KsEnc: {BitConverter.ToString(rapduDecryptedData)}");


                //----------------------------------------------------------------------- 1.7 Determine length of structure: L = ‘14’ +2 = 22 bytes
                // Extrahera längden från TLV-strukturen
                byte lengthField = rapduDecryptedData[1]; // Andra byte är längdfältet
                int L = lengthField + 2; // Lägg till 2 för tag och längdfält
                Console.WriteLine($"Determined length (L): {L} bytes");




                //----------------------------------------------------------------------- 3.Read Binary of remaining 18 bytes from offset 4:
                Console.WriteLine("----------------------------------------------------------------------- 3.Read Binary of remaining 18 bytes from offset 4: ");
                byte[] SSC3 = { 0x88, 0x70, 0x22, 0x12, 0x0C, 0x06, 0xC2, 0x2A };
                byte[] KsEncPart3 = { 0x97 ,0x9E ,0xC1 ,0x3B ,0x1C ,0xBF ,0xE9 ,0xDC ,0xD0 ,0x1A ,0xB0 ,0xFE ,0xD3 ,0x07 ,0xEA ,0xE5 };
                byte[] KSMacParitet3 = { 0xF1, 0xCB, 0x1F, 0x1F, 0xB5, 0xAD, 0xF2, 0x08, 0x80, 0x6B, 0x89, 0xDC, 0x57, 0x9D, 0xC1, 0xF8 };


                //-----------------------------------------------------------------------a Mask class byte and pad command header: CmdHeader = ‘0C-B0-00-04-80-00-00-00’ - 0C-B0-00-04-80-00-00-00 - Rätt
                byte[] cmdHeaderRb2 = { 0x0C, 0xB0, 0x00, 0x04, 0x80, 0x00, 0x00, 0x00 }; 
                Console.WriteLine($"CmdHeader -Read Binary2: {BitConverter.ToString(cmdHeaderRb2)}");

                //-----------------------------------------------------------------------b: Build DO‘97’: DO97 = ‘97-01-12 - 97-01-12 - Rätt
                byte[] DO97Rb2 = { 0x97, 0x01, 0x12 }; // Le = 18 (0x12)
                Console.WriteLine($"DO97 -Read Binary2: {BitConverter.ToString(DO97Rb2)}");

                ////-----------------------------------------------------------------------c:Concatenate CmdHeader and DO‘97’: M = ‘0C-B0-00-04-80-00-00-00-97-01-12’ - 0C-B0-00-04-80-00-00-00-97-01-12 - Rätt
                byte[] mRb2 = cmdHeaderRb2.Concat(DO97Rb2).ToArray();
                Console.WriteLine($"M -Read Binary2: {BitConverter.ToString(mRb2)}");

                //-----------------------------------------------------------------------d: Compute MAC of M:
                //-----------------------------------------------------------------------i. Increment SSC with 1: SSC = ‘88-70-22-12-0C-06-C2-2B’ - 88-70-22-12-0C-06-C2-2B - Rätt
                IncrementSSC(ref SSC);
                Console.WriteLine($"SSC -Read Binary2: {BitConverter.ToString(SSC)}");

                //-----------------------------------------------------------------------ii. Concatenate SSC and M and add padding: N = ‘88-70-22-12-0C-06-C2-2B-0C-B0-00-04-80-00-00-00-97-01-12-80-00-00-00-00 - Rätt
                //                                                                                                             Recieved: 88-70-22-12-0C-06-C2-2B-0C-B0-00-04-80-00-00-00-97-01-12-80-00-00-00-00
                byte[] paddedN = PadIso9797Method2(SSC.Concat(mRb2).ToArray());
                Console.WriteLine($"Padded N -Read Binary2: {BitConverter.ToString(paddedN)}");

                byte[] noPadN = SSC.Concat(mRb2).ToArray();
                //-----------------------------------------------------------------------iii. Compute MAC over N with KSMAC: CC = ‘2E-A2-8A-70-F3-C7-B5-35’ - 2E-A2-8A-70-F3-C7-B5-35 - Rätt
                byte[] CCRb2 = ComputeMac3DES(noPadN, KSMacParitet); //KSMacParitet
                Console.WriteLine($"CC -Read Binary2: {BitConverter.ToString(CCRb2)}");

                //-----------------------------------------------------------------------e. Build DO‘8E’: DO8E = ‘8E-08-2E-A2-8A-70-F3-C7-B5-35’ - 8E-08-2E-A2-8A-70-F3-C7-B5-35 -Rätt
                byte[] DO8ERb2 = BuildDO8E(CCRb2);
                Console.WriteLine($"DO8E -Read Binary2: {BitConverter.ToString(DO8ERb2)}");

                //-----------------------------------------------------------------------f. Construct and send protected APDU: ProtectedAPDU = ‘0C-B0-00-04-0D-97-01-12-8E-08-2E-A2-8A-70-F3-C7-B5-35-00’ -Rätt
                //                                                                                                                    Recieved: 0C-B0-00-04-0D-97-01-12-8E-08-2E-A2-8A-70-F3-C7-B5-35-00
                byte[] protectedAPDURb2 = ConstructProtectedAPDU(cmdHeaderRb2, DO97Rb2, DO8ERb2);
                Console.WriteLine($"Protected APDU -Read Binary2: {BitConverter.ToString(protectedAPDURb2)}");

                //-----------------------------------------------------------------------g. Receive response APDU of eMRTD’s contactless IC:                - ?-Rätt
                //RAPDU = ‘87-19-01-FB-92-35-F4-E4-03-7F-23-27-DC-C8-96-4F-1F-9B-8C-30-F4-2C-8E-2F-FF-22-4A-99-02-90-00-8E-08-C8-B2-78-7E-AE-A0-7D-74-90-00  
                //Recieved:87-19-01-C0-A5-32-C4-18-BD-7E-F1-FF-B0-84-EB-3F-D5-3F-EE-31-C2-8D-56-F2-6C-22-F2-99-02-90-00-8E-08-FC-7E-92-72-18-DC-21-E0-90-00 This answer is with my passport. dummyData shows 69-88.
                byte[] respApdu = isoDep.Transceive(protectedAPDURb2);
                Console.WriteLine($"RAPDU -Read Binary2: {BitConverter.ToString(respApdu)}");

                //byte[] respApdu2 = { 0x87, 0x19, 0x01, 0xFB, 0x92, 0x35, 0xF4, 0xE4, 0x03, 0x7F, 0x23, 0x27, 0xDC, 0xC8, 0x96, 0x4F, 0x1F, 0x9B, 0x8C, 0x30, 0xF4, 0x2C, 0x8E, 0x2F, 0xFF, 0x22, 0x4A, 0x99, 0x02, 0x90, 0x00, 0x8E, 0x08, 0xC8, 0xB2, 0x78, 0x7E, 0xAE, 0xA0, 0x7D, 0x74, 0x90, 0x00 };

                //-----------------------------------------------------------------------h. Verify RAPDU CC by computing MAC of concatenation DO‘87’ and DO‘99’

                //-----------------------------------------------------------------------i.Increment SSC with 1: SSC = ‘88-70-22-12-0C-06-C2-2C’ - 88-70-22-12-0C-06-C2-2C -Rätt
                IncrementSSC(ref SSC);
                Console.WriteLine($"SSC -Read Binary2 RAPDU: {BitConverter.ToString(SSC)}");

                //byte[] SSC4 = { 0x88, 0x70, 0x22, 0x12, 0x0C, 0x06, 0xC2, 0x2C };
                //Console.WriteLine($"SSC4 -Read Binary2 RAPDU: {BitConverter.ToString(SSC4)}");

                Console.WriteLine("/----------------------------------------------------------------------/----------------------------------------------------------------------");

                VerifyRapduCC(respApdu, ref SSC, KSMacParitet, KSEncParitet);
                //----------------------------------------------------------------------- RESULT: EF.COM data = ‘60-14-5F-01-04-30-31-30-36-5F-36-06-30-34-30-30-30-30-5C-02-61-75
                //                                                                                               60-14-5F-01-04-30-31-30-37-5F-36-06-30-34-30-30-30-30-5C-06-61-75
                Console.WriteLine("/----------------------------------------------------------------------/----------------------------------------------------------------------");

                //--------------------------------------------------------------------  D.READ DG1
                Console.WriteLine("/--------------------------------------------------------------------.READ DG1 /-------------------------------------------------------------------- ");

                var svar = SelectDG1Secure(isoDep, KSEncParitet, KSMacParitet, ref SSC);
                if (svar)
                {
                    Console.WriteLine("Lyckad!");
                }
                else
                {
                    Console.WriteLine("Faild");
                }
                Console.WriteLine("/--------------------------------------------------------------------.READ DG1 /-------------------------------------------------------------------- ");
                return true;

            }
            catch (Exception ex)
            {
                Console.WriteLine($"BAC authentication error: {ex.Message}");
                return false;
            }
        }
        //----------------------------------------------------------------------- K och CC rätt

        public class DG2Parser
        {
            public class FaceImageInfo
            {
                public byte[] ImageData { get; set; }
                public string ImageFormat { get; set; }
                public int Width { get; set; }
                public int Height { get; set; }
            }

            public static FaceImageInfo ParseDG2(byte[] rawData)
            {
                try
                {
                    // Skapa en MemoryStream för att läsa datan
                    using (var ms = new MemoryStream(rawData))
                    using (var reader = new BinaryReader(ms))
                    {
                        // Hoppa över ASN.1 header och längd
                        SkipTag(reader);

                        // Hoppa över biometrisk information header
                        SkipTag(reader);

                        // Läs antal instanser (normalt 1)
                        SkipTag(reader);

                        // Läs bilddata
                        return ReadFaceImageData(reader);
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception("Fel vid parsning av DG2 data", ex);
                }
            }

            private static void SkipTag(BinaryReader reader)
            {
                // Läs tag
                reader.ReadByte();

                // Läs längd
                int length = ReadAsn1Length(reader);

                // Hoppa över data
                if (length > 0)
                {
                    reader.BaseStream.Position += length;
                }
            }

            private static int ReadAsn1Length(BinaryReader reader)
            {
                int length = reader.ReadByte();

                if (length > 0x80)
                {
                    int numLengthBytes = length - 0x80;
                    length = 0;

                    for (int i = 0; i < numLengthBytes; i++)
                    {
                        length = (length << 8) | reader.ReadByte();
                    }
                }

                return length;
            }

            private static FaceImageInfo ReadFaceImageData(BinaryReader reader)
            {
                var faceInfo = new FaceImageInfo();

                // Läs JPEG eller JPEG2000 header
                byte[] headerBytes = reader.ReadBytes(2);
                if (headerBytes[0] == 0xFF && headerBytes[1] == 0xD8)
                {
                    faceInfo.ImageFormat = "JPEG";
                }
                else if (headerBytes[0] == 0x00 && headerBytes[1] == 0x00)
                {
                    faceInfo.ImageFormat = "JPEG2000";
                }
                else
                {
                    throw new Exception("Okänt bildformat");
                }

                // Läs bilddata
                using (var imageMs = new MemoryStream())
                {
                    // Skriv tillbaka header
                    imageMs.Write(headerBytes, 0, headerBytes.Length);

                    // Läs resten av bilddatan
                    while (reader.BaseStream.Position < reader.BaseStream.Length)
                    {
                        imageMs.WriteByte(reader.ReadByte());
                    }

                    faceInfo.ImageData = imageMs.ToArray();
                }

                // Om du vill spara bilden till fil
                // File.WriteAllBytes("passport_photo.jpg", faceInfo.ImageData);

                return faceInfo;
            }

            // Hjälpmetod för att spara bilden
            public static void SaveImage(FaceImageInfo faceInfo, string filePath)
            {
                if (faceInfo?.ImageData == null)
                    throw new ArgumentNullException(nameof(faceInfo));

                File.WriteAllBytes(filePath, faceInfo.ImageData);
            }

            // Hjälpmetod för att konvertera till Base64
            public static string ConvertToBase64(FaceImageInfo faceInfo)
            {
                if (faceInfo?.ImageData == null)
                    throw new ArgumentNullException(nameof(faceInfo));

                return Convert.ToBase64String(faceInfo.ImageData);
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

        private Dictionary<string, string> ParseMRZ(string cleanMRZ)
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
        public void VerifyRapduCC(byte[] rapdu, ref byte[] ssc, byte[] ksMac, byte[] ksEnc)
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
            Console.WriteLine($"DecryptedData: {BitConverter.ToString(DecryptedData)}");
            Console.WriteLine($"EF.COM data: {BitConverter.ToString(efComData)}");
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
        private byte[] ParseEFComData(byte[] efComData)
        {
            int index = 0;
            byte[] value = null;

            Console.WriteLine("Parsing EF.COM data...");

            while (index < efComData.Length)
            {
                byte tag = efComData[index++];
                Console.WriteLine($"Tag: {tag:X2}");

                int length = efComData[index++];
                Console.WriteLine($"Length: {length}");

                value = efComData.Skip(index).Take(length).ToArray();
                index += length;

                Console.WriteLine($"Value: {BitConverter.ToString(value)}");
            }
                return value;
        }
        public static void ParseEfComData(byte[] efComData)
        {
            Console.WriteLine("Parsing EF.COM data...");
            int index = 0;

            if (efComData[index] == 0x60)
            {
                Console.WriteLine("Container tag (60) detected.");
                index++;
                int containerLength = efComData[index++];
                Console.WriteLine($"Container Length: {containerLength}");
                efComData = efComData.Skip(index).Take(containerLength).ToArray();
                index = 0;
            }

            while (index < efComData.Length)
            {
                try
                {
                    int tag = efComData[index++];
                    if ((tag & 0x1F) == 0x1F)
                    {
                        tag = (tag << 8) | efComData[index++];
                    }

                    int length = efComData[index++];

                    if (tag == 0x5C)
                    {
                        Console.WriteLine($"\nAnalyzing Tag 5C (Data Group List):");
                        Console.WriteLine($"Stated Length: {length} bytes");

                        // Extract all bytes according to stated length
                        byte[] dgSection = efComData.Skip(index).Take(length).ToArray();
                        Console.WriteLine($"All bytes in section: {BitConverter.ToString(dgSection)}");

                        Console.WriteLine("\nDetailed byte analysis:");
                        for (int i = 0; i < dgSection.Length; i++)
                        {
                            byte currentByte = dgSection[i];
                            string byteType;

                            if (currentByte >= 0x61 && currentByte <= 0x75)
                            {
                                byteType = $"Valid DG identifier (DG{currentByte - 0x60})";
                            }
                            else if (currentByte == 0x00)
                            {
                                byteType = "Null byte (possible padding)";
                            }
                            else if (currentByte == 0x80)
                            {
                                byteType = "Padding marker (BER-TLV padding)";
                            }
                            else
                            {
                                byteType = "Unknown purpose";
                            }

                            Console.WriteLine($"Byte {i + 1}: {currentByte:X2} - {byteType}");
                        }

                        // Calculate actual DG content
                        var validDGs = dgSection.Where(b => b >= 0x61 && b <= 0x75).ToList();
                        Console.WriteLine($"\nNumber of valid DG identifiers found: {validDGs.Count}");
                        Console.WriteLine($"Valid DGs: {string.Join(", ", validDGs.Select(b => $"DG{b - 0x60}"))}");

                        // Show remaining space
                        int unusedSpace = length - validDGs.Count;
                        if (unusedSpace > 0)
                        {
                            Console.WriteLine($"Unused space: {unusedSpace} bytes");
                        }
                    }
                    else
                    {
                        byte[] value = efComData.Skip(index).Take(length).ToArray();
                        index += length;

                        switch (tag)
                        {
                            case 0x5F01:
                                Console.WriteLine($"LDS Version: {Encoding.ASCII.GetString(value)}");
                                break;
                            case 0x5F36:
                                Console.WriteLine($"Unicode Version: {Encoding.ASCII.GetString(value)}");
                                break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error during parsing: {ex.Message}");
                    break;
                }
            }
        }

        private bool SelectDG1Secure(IsoDep isoDep, byte[] KSEnc, byte[] KSMac, ref byte[] SSC)
        {
            try
            {
                // 1. Bygg APDU-headern
                byte[] cmdHeader = new byte[]
                {
                0x0C, 0xA4, 0x02, 0x0C, // CLA, INS, P1, P2
                0x80, 0x00, 0x00, 0x00  // Padding (Mask)
                };
                Console.WriteLine($"-cmdHeader-: {BitConverter.ToString(cmdHeader)}");


                // 2. Lägg till och padd datafältet
                byte[] data = new byte[] { 0x01, 0x01 }; // File ID för DG1
                byte[] paddedData = PadIso9797Method2(data);
                Console.WriteLine($"-Padded Data-: {BitConverter.ToString(paddedData)}");

                // 3. Kryptera datafältet med KSEnc
                byte[] encryptedData = EncryptWithKEnc3DES(paddedData, KSEnc);
                Console.WriteLine($"Encrypted Data with KsEnc: {BitConverter.ToString(encryptedData)}");


                // 4. Bygg DO87
                byte[] DO87 = BuildDO87(encryptedData);
                Console.WriteLine($"-DO87-: {BitConverter.ToString(DO87)}");


                // 5. Kombinera CmdHeader och DO87
                byte[] M = cmdHeader.Concat(DO87).ToArray();
                Console.WriteLine($"-M-: {BitConverter.ToString(M)}");


                // 6. Beräkna MAC för M
                IncrementSSC(ref SSC); // Öka SSC
                Console.WriteLine($"Incremented SSC: {BitConverter.ToString(SSC)}");

                byte[] NNopad = SSC.Concat(M).ToArray();
                byte[] N = PadIso9797Method2(NNopad);
                Console.WriteLine($"-NNopad-: {BitConverter.ToString(NNopad)}");
                Console.WriteLine($"-N-: {BitConverter.ToString(N)}");


                byte[] CC = ComputeMac3DES(NNopad, KSMac); // Beräkna MAC utan padding
                Console.WriteLine($"-CC- (MAC over N with KSMAC): {BitConverter.ToString(CC)}");


                // 7. Bygg DO8E
                byte[] DO8E = BuildDO8E(CC);
                Console.WriteLine($"DO8E: {BitConverter.ToString(DO8E)}");


                // 8. Konstruera och skicka den skyddade APDU:n
                byte[] protectedAPDU = ConstructProtectedAPDU(cmdHeader, DO87, DO8E);
                Console.WriteLine($"Protected APDU: {BitConverter.ToString(protectedAPDU)}");

                byte[] RAPDU = isoDep.Transceive(protectedAPDU);
                Console.WriteLine($"RAPDU: {BitConverter.ToString(RAPDU)}");

                // 9. Verifiera RAPDU
                VerifyRapduCC(RAPDU, ref SSC, KSMac, KSEnc);

                Console.WriteLine("DG1.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during DG1 selection: {ex.Message}");
                return false;
            }
        }

        //Funkar bra
        public List<byte[]> ReadCompleteDG1(IsoDep isoDep, byte[] KSEnc, byte[] KSMac, ref byte[] SSC)
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
                        Console.WriteLine($"Error reading DG1: {BitConverter.ToString(RAPDU)}");
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

                    Console.WriteLine($"Decrypted Data (Offset {offset}): {BitConverter.ToString(decryptedData)}");

                    // Kontrollera om sista segmentet lästs
                    if (decryptedData.Length < 0x20) // Mindre än maximalt möjligt per segment
                    {
                        Console.WriteLine("End of DG1 reached.");
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

      





        private byte[] BuildEfComData(byte[] decryptedData)
        {
            // Header för EF.COM data
            byte[] header = { 0x60, 0x14, 0x5F, 0x01 };

            // Kombinera header och avkodad data
            return header.Concat(decryptedData).ToArray();
        }

        private byte[] ComputeMac3DES2(byte[] data, byte[] ksMac)
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

        private byte[] ExtractDO8E2(byte[] rapdu)
        {
            // DO8E startar med taggen 0x8E
            int index = Array.IndexOf(rapdu, (byte)0x8E);
            if (index == -1) throw new InvalidOperationException("DO8E not found in RAPDU.");

            int length = rapdu[index + 1]; // DO8E längd
            return rapdu.Skip(index).Take(2 + length).ToArray(); // Tag + Längd + Data
        }

        private byte[] ExtractDO87(byte[] rapdu)
        {
            // DO87 startar med taggen 0x87
            int index = Array.IndexOf(rapdu, (byte)0x87);
            if (index == -1) throw new InvalidOperationException("DO87 not found in RAPDU.");

            int length = rapdu[index + 1]; // DO87 längd
            return rapdu.Skip(index).Take(2 + length).ToArray(); // Tag + Längd + Data
        }

        private byte[] ExtractDO99(byte[] rapdu)
        {
            // DO99 startar med taggen 0x99
            int index = Array.IndexOf(rapdu, (byte)0x99);
            if (index == -1) throw new InvalidOperationException("DO99 not found in RAPDU.");

            return rapdu.Skip(index).Take(4).ToArray(); // Tag (0x99) + 2 bytes data + 2 bytes SW
        }
        //----------------------------------------------------------------------- last in not sure

        private byte[] DecryptDO87WithKSEnc(byte[] do87, byte[] ksEnc)
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
                    Console.WriteLine($"Decrypted Data: {BitConverter.ToString(decryptedData)}");

                    // Returnera utan padding
                    return RemovePadding(decryptedData);
                }
            }
        }

        private byte[] RemovePadding(byte[] data)
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
        //----------------------------------------------------------------------- last in


        //----------------------------------------------------------------------- K och CC rätt


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
            //if (KMac.Length != 16 && KMac.Length != 24)
            //    throw new ArgumentException("Key length must be 16 or 24 bytes for 3DES");

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

        private byte[] DecryptWithKEnc3DES(byte[] data, byte[] KEnc)
        {
            using (var tripleDes = TripleDES.Create())
            {
                tripleDes.Key = KEnc;               // 3DES-nyckel (24 bytes)
                tripleDes.Mode = CipherMode.CBC;
                tripleDes.Padding = PaddingMode.None;
                tripleDes.IV = new byte[8];         // IV = 8 nollbytes


                var ngt = tripleDes.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);

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

        private byte[] BuildDO8E(byte[] mac)
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

        byte[] ConstructProtectedAPDU(byte[] cmdHeader, byte[] DO87, byte[] DO8E)
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

        byte[] ExtractDO8E(byte[] rapdu)
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

        byte[] ExtractEncryptedDataFromDO87(byte[] DO87)
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

        private byte[] ExtractDO87FromRAPDU(byte[] rapdu)
        {
            if (rapdu == null || rapdu.Length < 2)
            {
                throw new ArgumentException("Invalid RAPDU. Must contain at least a status word.");
            }

            // Exclude the last two bytes (status word SW1-SW2)
            int dataLength = rapdu.Length - 2;
            byte[] data = rapdu.Take(dataLength).ToArray();

            int currentIndex = 0;
            while (currentIndex < data.Length)
            {
                byte tag = data[currentIndex++];

                // If tag is 0x87 (DO87), process it
                if (tag == 0x87)
                {
                    // Get the length of the DO87 object
                    byte lengthIndicator = data[currentIndex++];
                    int length = lengthIndicator;

                    if (length > 127) // Handle cases where length is extended (multi-byte)
                    {
                        int additionalBytes = lengthIndicator & 0x7F;
                        length = 0;
                        for (int i = 0; i < additionalBytes; i++)
                        {
                            length = (length << 8) | data[currentIndex++];
                        }
                    }

                    // Extract the full DO87 (tag + length + content)
                    byte[] fullDO87 = new byte[2 + length];
                    fullDO87[0] = tag; // Include the tag (0x87)
                    fullDO87[1] = (byte)lengthIndicator; // Include the length
                    Array.Copy(data, currentIndex, fullDO87, 2, length);
                    return fullDO87;
                }
                else
                {
                    // Skip to the next tag (handle non-DO87 parts of the RAPDU)
                    byte lengthIndicator = data[currentIndex++];
                    int length = lengthIndicator;

                    if (length > 127) // Handle cases where length is extended (multi-byte)
                    {
                        int additionalBytes = lengthIndicator & 0x7F;
                        length = 0;
                        for (int i = 0; i < additionalBytes; i++)
                        {
                            length = (length << 8) | data[currentIndex++];
                        }
                    }
                    currentIndex += length; // Skip the content of the current tag
                }
            }

            throw new InvalidOperationException("DO87 not found in RAPDU.");
        }

        private byte[] ExtractDO99FromRAPDU(byte[] rapdu)
        {
            // Kontrollera att RAPDU är tillräckligt lång för att innehålla DO99 och SW1-SW2
            if (rapdu.Length < 4)
            {
                throw new ArgumentException("RAPDU är för kort för att innehålla DO99 och statusbytes (SW1-SW2).");
            }

            // DO99 är vanligtvis precis innan SW1-SW2 i RAPDU
            int do99Length = 4; // DO99 är 4 bytes: tag (1 byte), längd (1 byte), och data (2 bytes)
            int do99StartIndex = rapdu.Length - do99Length;

            // Extrahera DO99
            byte[] do99 = new byte[do99Length];
            Array.Copy(rapdu, do99StartIndex, do99, 0, do99Length);

            // Logga resultatet
            Console.WriteLine($"DO99: {BitConverter.ToString(do99)}");

            return do99;
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
