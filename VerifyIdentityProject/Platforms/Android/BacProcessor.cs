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

                //-------------------------------------------------------------------- 2.Calculate XOR of KIFD and KIC. That gets out Kseed.
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
                    0x01, 0x1E,  // File ID för EF.COM
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

                byte[] rapduEncryptedData = DecryptWithKEnc3DES(encryptDataFromDO87, KSEncParitet); //KSEncParitet
                Console.WriteLine($"Decrypted Data with KsEnc: {BitConverter.ToString(rapduEncryptedData)}");


                //----------------------------------------------------------------------- 1.7 Determine length of structure: L = ‘14’ +2 = 22 bytes
                // Extrahera längden från TLV-strukturen
                byte lengthField = rapduEncryptedData[1]; // Andra byte är längdfältet
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

                byte[] respApdu2 = { 0x87, 0x19, 0x01, 0xFB, 0x92, 0x35, 0xF4, 0xE4, 0x03, 0x7F, 0x23, 0x27, 0xDC, 0xC8, 0x96, 0x4F, 0x1F, 0x9B, 0x8C, 0x30, 0xF4, 0x2C, 0x8E, 0x2F, 0xFF, 0x22, 0x4A, 0x99, 0x02, 0x90, 0x00, 0x8E, 0x08, 0xC8, 0xB2, 0x78, 0x7E, 0xAE, 0xA0, 0x7D, 0x74, 0x90, 0x00 };

                //-----------------------------------------------------------------------h. Verify RAPDU CC by computing MAC of concatenation DO‘87’ and DO‘99’

                //-----------------------------------------------------------------------i.Increment SSC with 1: SSC = ‘88-70-22-12-0C-06-C2-2C’ - 88-70-22-12-0C-06-C2-2C -Rätt
                IncrementSSC(ref SSC);
                Console.WriteLine($"SSC -Read Binary2 RAPDU: {BitConverter.ToString(SSC)}");

                //-----------------------------------------------------------------------ii. Concatenate SSC, DO‘87’ and DO‘99’ and add padding: -extract DO‘87’ and DO‘99’ from RPADU-
                //                                                                          K = ‘88-70-22-12-0C-06-C2-2C-87-19-01-FB-92-35-F4-E4-03-7F-23-27-DC-C8-96-4F-1F-9B-8C-30-F4-2C-8E-2F-FF-22-4A-99-02-90-00’ - Rätt
                //                                                                     Recieved: 88-70-22-12-0C-06-C2-2C-87-19-01-FB-92-35-F4-E4-03-7F-23-27-DC-C8-96-4F-1F-9B-8C-30-F4-2C-8E-2F-FF-22-4A-7D-74-90-00
                byte[] extractedDO87Erb2 = ExtractDO87FromRAPDU(respApdu);
                Console.WriteLine($"Extracted DO87E -Read Binary2: {BitConverter.ToString(extractedDO87Erb2)}");
                byte[] Do99rb2 = ExtractDO99FromRAPDU(respApdu);
                Console.WriteLine($"Extracted DO99 -Read Binary2: {BitConverter.ToString(Do99rb2)}");
                //byte[] kRb2 = PadIso9797Method2(SSC.Concat(extractedDO87Erb2).Concat(Do99rb2).ToArray()); //comment this out because it added extra padding(80) at the end. EC-74-6B-6A-C9-2F-E5-F2
                byte[] kRb2 = SSC.Concat(extractedDO87Erb2).Concat(Do99rb2).ToArray();
                Console.WriteLine($"K - (Read Binary2) Padded-data: {BitConverter.ToString(kRb2)}");

                //-----------------------------------------------------------------------iii. Compute MAC with KSMAC: CC’ = ‘C8-B2-78-7E-AE-A0-7D-74’
                byte[] CC3 = ComputeMac3DES(kRb2, KSMacParitet); //KSMacParitet
                Console.WriteLine($"CC -Read Binary2 RAPDU: {BitConverter.ToString(CC3)}");

                //-----------------------------------------------------------------------iv. Compare CC’ with data of DO‘8E’ of RAPDU ‘C8-B2-78-7E-AE-A0-7D-74’ == ‘C8B2787EAEA07D74’ ? YES.
                byte[] extractedDO8E2 = ExtractDO8E(respApdu);
                Console.WriteLine($"DO8E -Read Binary2 RAPDU: {BitConverter.ToString(extractedDO8E2)}");

                if (!CC3.SequenceEqual(extractedDO8E2))
                {
                    Console.WriteLine("CC mismatch! RAPDU validation failed.");
                }
                else
                {
                Console.WriteLine("CC verification succeeded.");

                }
                //-----------------------------------------------------------------------ivv) Decrypt data of DO‘87’ with KSEnc: DecryptedData = ‘04303130365F36063034303030305C026175’
                //----------------------------------------------------------------------- RESULT: EF.COM data = ‘60145F0104303130365F36063034303030305C026175

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
