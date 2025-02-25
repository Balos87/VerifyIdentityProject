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
using static VerifyIdentityProject.Platforms.Android.BacProcessor;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureMessage
    {
        private IsoDep _isoDep;
        private byte[] _ksEnc;
        private byte[] _ksMac;
        private byte[] _ssc;
        private string _mrz;

        public SecureMessage(byte[] ksEnc, byte[] ksMac, IsoDep isoDep)
        {
            _ksEnc = ksEnc;
            _ksMac = ksMac;
            _isoDep = isoDep;
            _ssc = new byte[16];
        }
        public byte[] SelectApplication()
        {
            //var ssc = new byte[16]; // PACE: 16 bytes av nollor
            Console.WriteLine("------------------------------------------------------------Select application with secure message started...");
            Console.WriteLine("[DOTNET] Initial SSC: " + BitConverter.ToString(_ssc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsEnc: " + BitConverter.ToString(_ksEnc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsMac: " + BitConverter.ToString(_ksMac).Replace("-", " "));

            // Öka SSC före varje kommando
            IncrementSSC(ref _ssc);
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            // Original command data för select application
            byte[] commandData = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

            // 1. Padda data för kryptering
            byte[] paddedData = PadData(commandData);
            Console.WriteLine("[DOTNET] Padded data: " + BitConverter.ToString(paddedData).Replace("-", " "));

            // 2. Kryptera data med AES-CBC
            byte[] encryptedData = EncryptData(paddedData, _ssc);
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
            byte[] mac = CalculateMAC(dataToMac, _ssc);
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
            IncrementSSC(ref _ssc);
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            try
            {
                VerifyResponse(response, _ssc, _ksMac);
                Console.WriteLine("Response verification successful");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Response verification failed: {ex.Message}");
            }
            return response;
        }
        public string SelectDG1()
        {
            Console.WriteLine("------------------------------------------------------------Select DG1 with secure message started...");
            //var ssc = new byte[16]; // PACE: 16 bytes av nollor
            Console.WriteLine("[DOTNET] Initial SSC: " + BitConverter.ToString(_ssc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsEnc: " + BitConverter.ToString(_ksEnc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsMac: " + BitConverter.ToString(_ksMac).Replace("-", " "));

            // Öka SSC före varje kommando
            IncrementSSC(ref _ssc);
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            // Original command data för DG1
            byte[] commandData = new byte[] { 0x01, 0x01 };

            // 1. Padda data för kryptering
            byte[] paddedData = PadData(commandData);
            Console.WriteLine("[DOTNET] Padded data: " + BitConverter.ToString(paddedData).Replace("-", " "));

            // 2. Kryptera data med AES-CBC
            byte[] encryptedData = EncryptData(paddedData, _ssc);
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
            byte[] mac = CalculateMAC(dataToMac, _ssc);
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
            IncrementSSC(ref _ssc);
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            try
            {
                VerifyResponse(response, _ssc, _ksMac);
                Console.WriteLine("Response verification successful");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Response verification failed: {ex.Message}");
            }

            //----------------------------------------------------------------------- 1 Read Binary of first four bytes
            Console.WriteLine("/-----------------------------------------------------------------------  Read Binary of DG");
            List<byte[]> dg1Segments = ReadCompleteDG(_isoDep, _ksEnc, _ksMac, ref _ssc);

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
                _mrz = fullMrz;
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

            return _mrz;
        }
        public byte[] SelectDG2()
        {
            Console.WriteLine("------------------------------------------------------------Select DG2 with secure message started...");
            //var ssc = new byte[16]; // PACE: 16 bytes av nollor
            Console.WriteLine("[DOTNET] Initial SSC: " + BitConverter.ToString(_ssc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsEnc: " + BitConverter.ToString(_ksEnc).Replace("-", " "));
            Console.WriteLine("[DOTNET] KsMac: " + BitConverter.ToString(_ksMac).Replace("-", " "));

            // Öka SSC före varje kommando
            IncrementSSC(ref _ssc);
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            // Original command data för DG1
            byte[] commandData = new byte[] { 0x01, 0x02 };

            // 1. Padda data för kryptering
            byte[] paddedData = PadData(commandData);
            Console.WriteLine("[DOTNET] Padded data: " + BitConverter.ToString(paddedData).Replace("-", " "));

            // 2. Kryptera data med AES-CBC
            byte[] encryptedData = EncryptData(paddedData, _ssc);
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
            byte[] mac = CalculateMAC(dataToMac, _ssc);
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
            IncrementSSC(ref _ssc);
            Console.WriteLine("[DOTNET] SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            try
            {
                VerifyResponse(response, _ssc, _ksMac);
                Console.WriteLine("Response verification successful");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Response verification failed: {ex.Message}");
            }

            //----------------------------------------------------------------------- All Read Binary 
            Console.WriteLine("/-----------------------------------------------------------------------  Read Binary of DG");
            List<byte[]> dg2Segments = ReadCompleteDG(_isoDep, _ksEnc, _ksMac, ref _ssc);
            Console.WriteLine($"amount returned segment data: {dg2Segments.Count}");

            var completeData = dg2Segments.SelectMany(x => x).ToArray();
            Console.WriteLine($"Complete DG2 Data: {BitConverter.ToString(completeData)}");
            Console.WriteLine($"Complete DG2 Data.length: {completeData.Length}");
            Console.WriteLine($"First 20 bytes: {BitConverter.ToString(completeData.Take(20).ToArray())}");
            Console.WriteLine($"Last 20 bytes: {BitConverter.ToString(completeData.Skip(completeData.Length - 20).Take(20).ToArray())}");

            var imgDataInBytes = DG2Parser.ParseDG2Pace(completeData);

            Console.WriteLine("/----------------------------------------------------------------------- DG2-data process finished!");

            return imgDataInBytes;
        }

        //---------------------------------------------------------------------------------------------------readbinary stuff
        public List<byte[]> ReadCompleteDG(IsoDep isoDep, byte[] KSEnc, byte[] KSMac, ref byte[] SSC)
        {
            try
            {
                List<byte[]> fullData = new List<byte[]>();
                int offset = 0;
                const int blockSize = 0x20; // Standardstorlek för block i MRTD-kommunikation (32 bytes)

                while (true)
                {
                    Console.WriteLine($"------------------Started Reading DG at offset: {offset}");

                    // Steg 1: Bygg READ BINARY-kommando för nuvarande offset
                    byte[] cmdHeader = { 0x0C, 0xB0, (byte)(offset >> 8), (byte)(offset & 0xFF), 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    Console.WriteLine($"cmdHeader: {BitConverter.ToString(cmdHeader)}");

                    byte[] DO97 = { 0x97, 0x01, (byte)blockSize };
                    Console.WriteLine($"DO97: {BitConverter.ToString(DO97)}");

                    byte[] M = cmdHeader.Concat(DO97).ToArray();
                    Console.WriteLine($"M (cmdHeader+DO97): {BitConverter.ToString(M)}");


                    IncrementSSC(ref SSC);

                    byte[] NNoPad = M;
                    byte[] N = PadData(NNoPad);
                    Console.WriteLine($"N (SSC+M+Padd): {BitConverter.ToString(N)}");


                    byte[] CC = CalculateMAC(N, SSC);
                    Console.WriteLine($"CC: {BitConverter.ToString(CC)}");

                    byte[] DO8E = BuildDO8E(CC);
                    Console.WriteLine($"DO8E: {BitConverter.ToString(DO8E)}");

                    byte[] protectedAPDU = ConstructProtectedAPDU(cmdHeader, DO97, DO8E);
                    Console.WriteLine($"Sending Protected APDU: {BitConverter.ToString(protectedAPDU)}");

                    // Steg 2: Skicka kommando till DG1
                    byte[] RAPDU = isoDep.Transceive(protectedAPDU);
                    Console.WriteLine($"Response: {BitConverter.ToString(RAPDU)}");
                    bool success = IsSuccessfulResponse(RAPDU);
                    if(!success)
                    {
                        Console.WriteLine($"Response failed. SW-{BitConverter.ToString(RAPDU)} ");
                        break;
                    }



                    // Steg 3: Kontrollera svar och verifiera CC
                    IncrementSSC(ref SSC);
                    VerifyRapduCC(RAPDU, ref SSC, KSMac, KSEnc);

                    // Extrahera och dekryptera data från RAPDU
                    byte[] do87 = ExtractDO87(RAPDU);
                    byte[] encryptedData = ExtractEncryptedDataFromDO87(do87);
                    byte[] decryptedData = DecryptData(encryptedData, SSC);

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
                    Console.WriteLine($"----------------------------End of loop at offset: {offset}");
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
        public void VerifyRapduCC(byte[] rapdu, ref byte[] SSC, byte[] ksMac, byte[] ksEnc)
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
            Console.WriteLine($"SSC: {BitConverter.ToString(SSC)}");


            // 2. build K SSC, DO‘87’ and DO‘99’ and add padding
            byte[] concatenatedData = do87.Concat(do99).ToArray();
            byte[] k = PadData(concatenatedData);

            Console.WriteLine($"Concatenated (SSC + DO87 + DO99): {BitConverter.ToString(concatenatedData)}");
            Console.WriteLine($"K (DO87+DO99+pad): {BitConverter.ToString(k)}");

            //-----------------------------------------------------------------------iii. Compute MAC with KSMAC: CC’ = ‘C8-B2-78-7E-AE-A0-7D-74’ - C8-B2-78-7E-AE-A0-7D-74 - Rätt
            byte[] calculatedMacCC = CalculateMAC(k, SSC);
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

        }
        static byte[] ConstructProtectedAPDU(byte[] cmdHeader, byte[] DO97, byte[] DO8E)
        {
            // Lc = Length of DO87 + DO8E
            byte[] shortCmdHeader = cmdHeader.Take(4).ToArray();
            byte lc = (byte)(DO97.Length + DO8E.Length);

            // Bygg Protected APDU
            byte[] protectedAPDU = new byte[shortCmdHeader.Length + 1 + DO97.Length + DO8E.Length + 1];
            Array.Copy(shortCmdHeader, 0, protectedAPDU, 0, shortCmdHeader.Length); // Kopiera CmdHeader
            protectedAPDU[shortCmdHeader.Length] = lc;                        // Lägg till Lc
            Array.Copy(DO97, 0, protectedAPDU, shortCmdHeader.Length + 1, DO97.Length); // Lägg till DO87
            Array.Copy(DO8E, 0, protectedAPDU, shortCmdHeader.Length + 1 + DO97.Length, DO8E.Length); // Lägg till DO8E
            protectedAPDU[^1] = 0x00;                                   // Lägg till Le (0x00)
            //0C-B0-00-00-0D    -97-01-04-  8E-08-  ED-67-05-41-7E-96-BA-55 -00
            //0C-B0-00-00-0D    -97-01-20-  8E-08-  3F-16-75-8A-7A-43-0D-5E -00
            return protectedAPDU;
        }
        private static byte[] ExtractDO87(byte[] rapdu)
        {
            // DO87 startar med taggen 0x87
            int index = Array.IndexOf(rapdu, (byte)0x87);
            if (index == -1) throw new InvalidOperationException("DO87 not found in RAPDU.");

            int length = rapdu[index + 1]; // DO87 längd
            return rapdu.Skip(index).Take(2 + length).ToArray(); // Tag + Längd + Data
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
        private static byte[] ExtractDO99(byte[] rapdu)
        {
            // DO99 startar med taggen 0x99
            int index = Array.IndexOf(rapdu, (byte)0x99);
            if (index == -1) throw new InvalidOperationException("DO99 not found in RAPDU.");

            return rapdu.Skip(index).Take(4).ToArray(); // Tag (0x99) + 2 bytes data + 2 bytes SW
        }
        private static byte[] ExtractDO8E2(byte[] rapdu)
        {
            // DO8E startar med taggen 0x8E
            int index = Array.IndexOf(rapdu, (byte)0x8E);
            if (index == -1) throw new InvalidOperationException("DO8E not found in RAPDU.");

            int length = rapdu[index + 1]; // DO8E längd
            return rapdu.Skip(index).Take(2 + length).ToArray(); // Tag + Längd + Data
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
        //---------------------------------------------------------------------------------------------------readbinary stuff
        private byte[] PadData(byte[] data)
        {
            int paddingLength = 16 - (data.Length % 16);
            byte[] paddedData = new byte[data.Length + paddingLength];
            Buffer.BlockCopy(data, 0, paddedData, 0, data.Length);
            paddedData[data.Length] = 0x80;
            return paddedData;
        }

        private byte[] DecryptData(byte[] paddedData, byte[] ssc)
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

                var decryptedData = aes.CreateDecryptor().TransformFinalBlock(paddedData, 0, paddedData.Length);

                return decryptedData;
            }
        }private byte[] EncryptData(byte[] paddedData, byte[] ssc)
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
        private static bool IsSuccessfulResponse(byte[] response)
        {
            Console.WriteLine("<-IsSuccessfulResponse->");
            if (response == null || response.Length < 2)
                return false;

            // Check the last two bytes for the status code
            return response[response.Length - 2] == 0x90 && response[response.Length - 1] == 0x00;
        }
    }
}
