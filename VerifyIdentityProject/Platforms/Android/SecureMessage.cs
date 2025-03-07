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
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using VerifyIdentityProject.Helpers;
using static VerifyIdentityProject.Platforms.Android.BacProcessor;
using static VerifyIdentityProject.Platforms.Android.DG2Parser;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureMessage
    {
        private IsoDep _isoDep;
        private byte[] _ksEnc;
        private byte[] _ksMac;
        private byte[] _ssc;
        private Dictionary<string, string> _dictionaryMrzData;

        public SecureMessage(byte[] ksEnc, byte[] ksMac, IsoDep isoDep)
        {
            _ksEnc = ksEnc;
            _ksMac = ksMac;
            _isoDep = isoDep;
            _ssc = new byte[16];
        }

        public byte[] SelectApplication()
        {
            SecureMessagingHelper secureMessagingHelper = new SecureMessagingHelper(_ksEnc, _ksMac);

            Console.WriteLine("------------------------------------------------------------Select application with secure message started...");
            Console.WriteLine("Initial SSC: " + BitConverter.ToString(_ssc).Replace("-", " "));
            Console.WriteLine("KsEnc: " + BitConverter.ToString(_ksEnc).Replace("-", " "));
            Console.WriteLine("KsMac: " + BitConverter.ToString(_ksMac).Replace("-", " "));

            // Increase SSC before each command
            secureMessagingHelper.IncrementSSCPace(ref _ssc);
            Console.WriteLine("SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            //Original command data for select application
            byte[] commandData = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

            // 1. Pad data for encryption
            byte[] paddedData = secureMessagingHelper.PadDataPace(commandData);
            Console.WriteLine("Padded command data: " + BitConverter.ToString(paddedData).Replace("-", " "));

            // 2. Encrypt data with AES-CBC
            byte[] encryptedData = secureMessagingHelper.EncryptDataPace(paddedData, _ssc);
            Console.WriteLine("Encrypted command data: " + BitConverter.ToString(encryptedData).Replace("-", " "));

            // 3. Build DO'87'
            byte[] do87 = secureMessagingHelper.BuildDO87Pace(encryptedData);
            Console.WriteLine("DO'87': " + BitConverter.ToString(do87).Replace("-", " "));

            // 4. Build data for MAC calculation
            byte[] paddedHeader = new byte[] { 0x0C, 0xA4, 0x04, 0x0C, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] dataToMac = secureMessagingHelper.ConcatenateArraysPace(paddedHeader, do87);
            Console.WriteLine("Padded CmdHeader + DO87: " + BitConverter.ToString(dataToMac).Replace("-", " "));


            dataToMac = secureMessagingHelper.PadDataPace(dataToMac);
            Console.WriteLine("Padded data to MAC: " + BitConverter.ToString(dataToMac).Replace("-", " "));

            // 5. Calculate MAC
            byte[] mac = secureMessagingHelper.CalculateMACPace(dataToMac, _ssc);
            Console.WriteLine("Calculated MAC: " + BitConverter.ToString(mac).Replace("-", " "));

            // 6. Build DO'8E'
            byte[] do8E = secureMessagingHelper.BuildDO8EPace(mac);
            Console.WriteLine("DO'8E': " + BitConverter.ToString(do8E).Replace("-", " "));

            // 7. Build final protected APDU
            byte[] protectedApdu = secureMessagingHelper.BuildProtectedAPDUPace(paddedHeader, do87, do8E);
            Console.WriteLine("Protected APDU: " + BitConverter.ToString(protectedApdu).Replace("-", " "));

            var response = _isoDep.Transceive(protectedApdu);
            Console.WriteLine("reponse: " + BitConverter.ToString(response).Replace("-", " "));


            // 8. Increase SSC for response verification
            secureMessagingHelper.IncrementSSCPace(ref _ssc);
            Console.WriteLine("SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            try
            {
                secureMessagingHelper.VerifyResponsePace(response, _ssc, _ksMac);
                Console.WriteLine("Response verification successful");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Response verification failed: {ex.Message}");
            }
            return response;
        }

        public Dictionary<string, string> SelectDG1()
        {
            SecureMessagingHelper secureMessagingHelper = new SecureMessagingHelper(_ksEnc, _ksMac);

            Console.WriteLine("------------------------------------------------------------Select DG1 with secure message started...");

            Console.WriteLine("Initial SSC: " + BitConverter.ToString(_ssc).Replace("-", " "));
            Console.WriteLine("KsEnc: " + BitConverter.ToString(_ksEnc).Replace("-", " "));
            Console.WriteLine("KsMac: " + BitConverter.ToString(_ksMac).Replace("-", " "));

            // Increase SSC before each command
            secureMessagingHelper.IncrementSSCPace(ref _ssc);
            Console.WriteLine("SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            // Original command data for DG1
            byte[] commandData = new byte[] { 0x01, 0x01 };

            // 1. Padded command data for encryption
            byte[] paddedData = secureMessagingHelper.PadDataPace(commandData);
            Console.WriteLine("Padded CmdData: " + BitConverter.ToString(paddedData).Replace("-", " "));

            // 2. Encrypt data with AES-CBC
            byte[] encryptedData = secureMessagingHelper.EncryptDataPace(paddedData, _ssc);
            Console.WriteLine("Encrypted data: " + BitConverter.ToString(encryptedData).Replace("-", " "));

            // 3. Build DO'87'
            byte[] do87 = secureMessagingHelper.BuildDO87Pace(encryptedData);
            Console.WriteLine("DO'87': " + BitConverter.ToString(do87).Replace("-", " "));

            // 4. Build data for calculating MAC
            byte[] paddedHeader = new byte[] { 0x0C, 0xA4, 0x02, 0x0C, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] dataToMac = secureMessagingHelper.ConcatenateArraysPace(paddedHeader, do87);
            Console.WriteLine("Padded cmdHeader + DO87: " + BitConverter.ToString(dataToMac).Replace("-", " "));

            // Pad the entire dataToMac (M) string
            dataToMac = secureMessagingHelper.PadDataPace(dataToMac);
            Console.WriteLine("Padded data to MAC: " + BitConverter.ToString(dataToMac).Replace("-", " "));

            // 5. Calculate MAC
            byte[] mac = secureMessagingHelper.CalculateMACPace(dataToMac, _ssc);
            Console.WriteLine("Calculated MAC: " + BitConverter.ToString(mac).Replace("-", " "));

            // 6. Build DO'8E'
            byte[] do8E = secureMessagingHelper.BuildDO8EPace(mac);
            Console.WriteLine("DO'8E': " + BitConverter.ToString(do8E).Replace("-", " "));

            // 7. Build final protected APDU
            byte[] protectedApdu = secureMessagingHelper.BuildProtectedAPDUPace(paddedHeader, do87, do8E);
            Console.WriteLine("Protected APDU: " + BitConverter.ToString(protectedApdu).Replace("-", " "));

            var response = _isoDep.Transceive(protectedApdu);
            Console.WriteLine("reponse: " + BitConverter.ToString(response).Replace("-", " "));

            // 8.Increase SSC for response verifying
            secureMessagingHelper.IncrementSSCPace(ref _ssc);
            Console.WriteLine("SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            try
            {
                secureMessagingHelper.VerifyResponsePace(response, _ssc, _ksMac);
                Console.WriteLine("Response verification successful");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Response verification failed: {ex.Message}");
            }

            //---------------------------------------------------------------------------- Read Binary
            Console.WriteLine("/-----------------------------------------------------------------------  Read Binary of DG");
            List<byte[]> dg1Segments = ReadCompleteDG(_isoDep, _ksEnc, _ksMac, ref _ssc);

            if (dg1Segments.Count > 0)
            {
                byte[] completeDG1 = dg1Segments.SelectMany(segment => segment).ToArray();
                Console.WriteLine($"Complete DG1 Data: {BitConverter.ToString(completeDG1)}");
                Console.WriteLine($"Complete DG1 Data.Length: {completeDG1.Length}");

                // To see first and last 20 bytes
                Console.WriteLine($"First 20 bytes: {BitConverter.ToString(completeDG1.Take(20).ToArray())}");
                Console.WriteLine($"Last 20 bytes: {BitConverter.ToString(completeDG1.Skip(completeDG1.Length - 20).Take(20).ToArray())}");

                //// To see all data, you must print in chunks
                //const int chunkSize = 100;
                //for (int i = 0; i < completeDG1.Length; i += chunkSize)
                //{
                //    int length = Math.Min(chunkSize, completeDG1.Length - i);
                //    var chunk = new byte[length];
                //    Array.Copy(completeDG1, i, chunk, 0, length);
                //    Console.WriteLine($"Chunk {i / chunkSize}: {BitConverter.ToString(chunk)}");
                //}

                var fullMrz = MRZByteParser.ParseMRZBytes(completeDG1);
                var splittedMrz = MRZByteParser.FormatMRZForBAC(fullMrz);
                Console.WriteLine($"Whole MRZ: {fullMrz}");
                Console.WriteLine($"Splitted MRZ:\n{splittedMrz}");

                var extractedInfoFromMrz = MRZParser.ParseMRZ(splittedMrz);

                _dictionaryMrzData = MRZParser.ToDictionary(extractedInfoFromMrz);

                var parsedMRZ = MRZParser.ParseMRZ(splittedMrz);

                foreach (var field in _dictionaryMrzData)
                {
                    Console.WriteLine($"{field.Key}: {field.Value}");
                }
            }
            Console.WriteLine("/----------------------------------------------------------------------- DG1 process finished!");

            return _dictionaryMrzData;
        }

        public async Task<byte[]> SelectDG2Async(string apiUrl)
        {
            SecureMessagingHelper secureMessagingHelper = new SecureMessagingHelper(_ksEnc, _ksMac);
            ReadBinaryHelper readBinaryHelper = new ReadBinaryHelper();

            Console.WriteLine("------------------------------------------------------------Select DG2 with secure message started...");
            Console.WriteLine("Initial SSC: " + BitConverter.ToString(_ssc).Replace("-", " "));
            Console.WriteLine("KsEnc: " + BitConverter.ToString(_ksEnc).Replace("-", " "));
            Console.WriteLine("KsMac: " + BitConverter.ToString(_ksMac).Replace("-", " "));

            // Increase SSC before each command
            secureMessagingHelper.IncrementSSCPace(ref _ssc);
            Console.WriteLine("SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            // Original command data for DG2
            byte[] commandData = new byte[] { 0x01, 0x02 };

            // 1. Pad data for encryption
            byte[] paddedData = secureMessagingHelper.PadDataPace(commandData);
            Console.WriteLine("Padded data: " + BitConverter.ToString(paddedData).Replace("-", " "));

            // 2. Encrypt data with AES-CBC
            byte[] encryptedData = secureMessagingHelper.EncryptDataPace(paddedData, _ssc);
            Console.WriteLine("Encrypted data: " + BitConverter.ToString(encryptedData).Replace("-", " "));

            // 3. Build DO'87'
            byte[] do87 = secureMessagingHelper.BuildDO87Pace(encryptedData);
            Console.WriteLine("DO'87': " + BitConverter.ToString(do87).Replace("-", " "));

            // 4. Build header for MAC calculation and concatenate with DO87
            byte[] paddedHeader = new byte[] { 0x0C, 0xA4, 0x02, 0x0C, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] dataToMac = secureMessagingHelper.ConcatenateArraysPace(paddedHeader, do87);
            Console.WriteLine("cmdHeader+DO87: " + BitConverter.ToString(dataToMac).Replace("-", " "));

            // Pad the entire dataToMac (M) string
            dataToMac = secureMessagingHelper.PadDataPace(dataToMac);
            Console.WriteLine("Padded data to MAC: " + BitConverter.ToString(dataToMac).Replace("-", " "));

            // 5. Calculate MAC
            byte[] mac = secureMessagingHelper.CalculateMACPace(dataToMac, _ssc);
            Console.WriteLine("Calculated MAC: " + BitConverter.ToString(mac).Replace("-", " "));

            // 6. Build DO'8E'
            byte[] do8E = secureMessagingHelper.BuildDO8EPace(mac);
            Console.WriteLine("DO'8E': " + BitConverter.ToString(do8E).Replace("-", " "));

            // 7. Build final protected APDU
            byte[] protectedApdu = secureMessagingHelper.BuildProtectedAPDUPace(paddedHeader, do87, do8E);
            Console.WriteLine("Protected APDU: " + BitConverter.ToString(protectedApdu).Replace("-", " "));

            // Send the APDU and receive the response
            var response = _isoDep.Transceive(protectedApdu);
            Console.WriteLine("response: " + BitConverter.ToString(response).Replace("-", " "));

            // 8. Increase SSC for response verification
            secureMessagingHelper.IncrementSSCPace(ref _ssc);
            Console.WriteLine("SSC after increment: " + BitConverter.ToString(_ssc).Replace("-", " "));

            try
            {
                secureMessagingHelper.VerifyResponsePace(response, _ssc, _ksMac);
                Console.WriteLine("Response verification successful");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Response verification failed: {ex.Message}");
            }

            // -----------------------------------------------------------------------Read Binary of DG (DG2 segments)
            Console.WriteLine("/-----------------------------------------------------------------------  Read Binary of DG");
            List<byte[]> dg2Segments = ReadCompleteDG(_isoDep, _ksEnc, _ksMac, ref _ssc);
            Console.WriteLine($"Amount returned segment data: {dg2Segments.Count}");

            var completeData = dg2Segments.SelectMany(x => x).ToArray();
            Console.WriteLine($"Complete DG2 Data: {BitConverter.ToString(completeData)}");
            Console.WriteLine($"Complete DG2 Data.length: {completeData.Length}");
            Console.WriteLine($"First 20 bytes: {BitConverter.ToString(completeData.Take(20).ToArray())}");
            Console.WriteLine($"Last 20 bytes: {BitConverter.ToString(completeData.Skip(completeData.Length - 20).Take(20).ToArray())}");

            // Call ParseDG2PaceAllJpegs ASYNC and WAIT for the result
            FaceImageInfo faceInfo = await DG2Parser.ParseDG2PaceAllJpegs(completeData, apiUrl, "passport_photo");

            byte[] imgDataInBytes = faceInfo.ImageData;

            Console.WriteLine("/----------------------------------------------------------------------- DG2-data process finished!");

            return imgDataInBytes;
        }

        //--------------------------------------------------------------------------------------------------- Readbinary
        public List<byte[]> ReadCompleteDG(IsoDep isoDep, byte[] KSEnc, byte[] KSMac, ref byte[] SSC)
        {
            try
            {
                ReadBinaryHelper readBinaryHelper = new ReadBinaryHelper();
                SecureMessagingHelper secureMessagingHelper = new SecureMessagingHelper(_ksEnc, _ksMac);
                List<byte[]> fullData = new List<byte[]>();
                int offset = 0;
                const int blockSize = 0x20; // Standard size for block in MRTD-communication (32 bytes)

                while (true)
                {
                    Console.WriteLine($"------------------Started Reading DG at offset: {offset}");

                    // Step 1: Build READ BINARY command for current offset
                    byte[] cmdHeader = { 0x0C, 0xB0, (byte)(offset >> 8), (byte)(offset & 0xFF), 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    Console.WriteLine($"cmdHeader: {BitConverter.ToString(cmdHeader)}");

                    byte[] DO97 = { 0x97, 0x01, (byte)blockSize };
                    Console.WriteLine($"DO97: {BitConverter.ToString(DO97)}");

                    byte[] M = cmdHeader.Concat(DO97).ToArray();
                    Console.WriteLine($"M (cmdHeader+DO97): {BitConverter.ToString(M)}");


                    secureMessagingHelper.IncrementSSCPace(ref SSC);

                    byte[] NNoPad = M;
                    byte[] N = secureMessagingHelper.PadDataPace(NNoPad);
                    Console.WriteLine($"N (SSC+M+Padd): {BitConverter.ToString(N)}");


                    byte[] CC = secureMessagingHelper.CalculateMACPace(N, SSC);
                    Console.WriteLine($"CC: {BitConverter.ToString(CC)}");

                    byte[] DO8E = secureMessagingHelper.BuildDO8EPace(CC);
                    Console.WriteLine($"DO8E: {BitConverter.ToString(DO8E)}");

                    byte[] protectedAPDU = ReadBinaryHelper.ConstructProtectedAPDUPace(cmdHeader, DO97, DO8E);
                    Console.WriteLine($"Sending Protected APDU: {BitConverter.ToString(protectedAPDU)}");

                    // Step 2: Send command to DG1
                    byte[] RAPDU = isoDep.Transceive(protectedAPDU);
                    Console.WriteLine($"Response: {BitConverter.ToString(RAPDU)}");
                    bool success = SecureMessagingHelper.IsSuccessfulResponsePace(RAPDU);
                    if(!success)
                    {
                        Console.WriteLine($"Response failed. SW-{BitConverter.ToString(RAPDU)} ");
                        break;
                    }

                    // step 3: Check response and verify CC
                    secureMessagingHelper.IncrementSSCPace(ref SSC);
                    readBinaryHelper.VerifyRapduCCPace(RAPDU, ref SSC, KSMac, KSEnc);

                    // Extract and decrypt data from RAPDU
                    byte[] do87 = ReadBinaryHelper.ExtractDO87Pace(RAPDU);
                    byte[] encryptedData = ReadBinaryHelper.ExtractEncryptedDataFromDO87Pace(do87);
                    byte[] decryptedData = secureMessagingHelper.DecryptDataPace(encryptedData, SSC);

                    // Add decrypted data to fullData
                    fullData.AddRange(decryptedData);
                    Console.WriteLine($"Decrypted Data added: {BitConverter.ToString(decryptedData)}");

                    Console.WriteLine($"Decrypted Data (Offset {offset}): {BitConverter.ToString(decryptedData)}");

                    // Check if last segment has been read
                    if (decryptedData.Length < 0x20) // Less than maximum possible per segment
                    {
                        Console.WriteLine("End of DG reached.");
                        break;
                    }

                    // Update offset for next block
                    offset += 0x20;
                    Console.WriteLine($"----------------------------End of loop at offset: {offset}");
                }

                // Return all combined data
                return fullData;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading DG1: {ex.Message}");
                return null;
            }
        }
    }
}
