using Android.Health.Connect.DataTypes.Units;
using Android.Nfc.Tech;
using Microsoft.Maui.Controls;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using VerifyIdentityProject.Helpers;
using Xamarin.Google.Crypto.Tink.Prf;
using static Android.Provider.MediaStore.Audio;

namespace VerifyIdentityProject.Platforms.Android
{
    public class PaceProcessor
    {
        private readonly IsoDep _isoDep;
        private static byte[] AID_MRTD = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };

        public PaceProcessor(IsoDep isoDep)
        {
            _isoDep = isoDep;
        }

        // Main method to perform PACE
        public static async Task<byte[]> PerformPace(IsoDep isoDep)
        {
            Console.WriteLine("<-PerformPace->");
            try
            {
                // Step 0: Select the passport application
                await SelectApplication(isoDep);

                // Step 1: Read CardAccess to get PACE parameters
                var cardAccess = await ReadCardAccess(isoDep);
                var validOids = ValidateAndListPACEInfoWithDescriptions(cardAccess);
                Console.WriteLine($"");
                Console.WriteLine("______Valid PACE Protocols:");
                //Fetch mrz data from secrets
                var secrets = GetSecrets.FetchSecrets();
                var mrzData = secrets?.MRZ_NUMBERS ?? string.Empty;
                Console.WriteLine($"mrzData: {mrzData}");

                foreach (var oid in validOids)
                {
                    if (OidEndsWith(oid, "4.2.4"))
                    {
                        Console.WriteLine($"OID: {BitConverter.ToString(oid)}");
                        await StartPaceProtocol(isoDep, mrzData, oid);
                        
                    }
                }
                Console.WriteLine("");
                Console.WriteLine("<---------------------------------------->");


                //// Step 2: MSE:Set AT command to initiate PACE
                // await InitializePace(paceInfo);

                //// Step 3: Get encrypted nonce from the passport
                // var encryptedNonce = await GetEncryptedNonce();

                //// Step 4: Decrypt the nonce using the password derived from the MRZ
                // var password = DerivePasswordFromMrz(mrz);
                // var decryptedNonce = DecryptNonce(encryptedNonce, password);

                //// Step 5: Generate and exchange ephemeral keys
                // var mappingData = await PerformMapping(decryptedNonce);
                // var (myKeyPair, theirPubKey) = await ExchangeEphemeralKeys(mappingData);

                //// Step 6: Calculate the shared secret
                // var sharedSecret = CalculateSharedSecret(myKeyPair, theirPubKey);
                byte[] sharedSecret = null;
                //// Step 7: Derive session keys
                // var (KSenc, KSmac) = DeriveSessionKeys(sharedSecret);

                //// Step 8: Perform Mutual Authentication
                // await PerformMutualAuthentication(KSenc, KSmac);

                return cardAccess;
            }
            catch (Exception ex)
            {
                throw new PaceException("The PACE process failed", ex);
            }
        }

        public static async Task StartPaceProtocol(IsoDep isoDep, string mrz, byte[] oid)
        {
            // Perform the PACE protocol.
            var pace = new PaceProtocol(isoDep, mrz, oid);
            bool success = await pace.PerformPaceProtocol();

            if (!success)
            {
                Console.WriteLine("❌ PACE authentication failed.");
                return;
            }

            Console.WriteLine("✅ PACE authentication succeeded! Secure Messaging can now be established.");

            // Initialize Secure Messaging with the derived session keys.
            SecureMessaging secureMessaging = new SecureMessaging(pace.KSEnc, pace.KSMAC, SecureMessaging.ComputeSSC());

            // ---- Reselect Passport Application (Unprotected SELECT) ----
            // Build the SELECT APDU using AID_MRTD (e.g. { A0, 00, 00, 02, 47, 10, 01 })
            byte[] selectAppApdu = new byte[] { 0x00, 0xA4, 0x04, 0x0C }
                 .Concat(new byte[] { (byte)AID_MRTD.Length })
                 .Concat(AID_MRTD)
                 .Concat(new byte[] { 0x00 })
                 .ToArray();

            Console.WriteLine($"🔹 Reselecting Passport Application with APDU: {BitConverter.ToString(selectAppApdu)}");
            byte[] selectAppResponse = await isoDep.TransceiveAsync(selectAppApdu);
            Console.WriteLine($"🔹 Passport Application SELECT response: {BitConverter.ToString(selectAppResponse)}");

            // Validate that the passport application was selected (SW = 90 00)
            if (selectAppResponse == null || selectAppResponse.Length < 2 ||
                selectAppResponse[selectAppResponse.Length - 2] != 0x90 ||
                selectAppResponse[selectAppResponse.Length - 1] != 0x00)
            {
                Console.WriteLine("❌ Passport Application selection failed.");
                return;
            }
            // ---- End Reselecting Passport Application ----

            // Now call SecureReadDG1 to read DG1 using a secure READ BINARY command.
            SecureReadDG1 secureReadDG1 = new SecureReadDG1(isoDep, secureMessaging);
            byte[] dg1Data = await secureReadDG1.ReadDG1Async();

            if (dg1Data != null && dg1Data.Length >= 2)
            {
                // Optionally, extract and check the status word from the decrypted response.
                int len = dg1Data.Length;
                byte sw1 = dg1Data[len - 2];
                byte sw2 = dg1Data[len - 1];
                if (sw1 == 0x90 && sw2 == 0x00)
                {
                    Console.WriteLine("📄 DG1 successfully read!");
                }
                else
                {
                    Console.WriteLine($"❌ DG1 read failed. Status: {sw1:X2} {sw2:X2}");
                }
            }
            else
            {
                Console.WriteLine("❌ DG1 read failed.");
            }
        }


        ////Could not select dg1
        //public static async Task StartPaceProtocol(IsoDep isoDep, string mrz, byte[] oid)
        //{
        //    // Perform the PACE protocol
        //    var pace = new PaceProtocol(isoDep, mrz, oid);
        //    bool success = await pace.PerformPaceProtocol();

        //    if (!success)
        //    {
        //        Console.WriteLine("❌ PACE authentication failed.");
        //        return;
        //    }

        //    Console.WriteLine("✅ PACE authentication succeeded! Secure Messaging can now be established.");

        //    // Initialize Secure Messaging using the derived session keys.
        //    SecureMessaging secureMessaging = new SecureMessaging(pace.KSEnc, pace.KSMAC, SecureMessaging.ComputeSSC());

        //    // ---- New Step: Reselect Passport Application ----
        //    // Build the SELECT APDU using the AID_MRTD (e.g. { A0, 00, 00, 02, 47, 10, 01 })
        //    byte[] selectAppApdu = new byte[] { 0x00, 0xA4, 0x04, 0x0C }
        //         .Concat(new byte[] { (byte)AID_MRTD.Length })
        //         .Concat(AID_MRTD)
        //         .Concat(new byte[] { 0x00 })
        //         .ToArray();

        //    Console.WriteLine($"🔹 Reselecting Passport Application with APDU: {BitConverter.ToString(selectAppApdu)}");
        //    byte[] selectAppResponse = await isoDep.TransceiveAsync(selectAppApdu);
        //    Console.WriteLine($"🔹 Passport Application SELECT response: {BitConverter.ToString(selectAppResponse)}");

        //    // Validate that the passport application was selected (SW = 90 00)
        //    if (selectAppResponse == null || selectAppResponse.Length < 2 ||
        //        selectAppResponse[selectAppResponse.Length - 2] != 0x90 ||
        //        selectAppResponse[selectAppResponse.Length - 1] != 0x00)
        //    {
        //        Console.WriteLine("❌ Passport Application selection failed.");
        //        return;
        //    }
        //    // ---- End of Application Reselection ----

        //    // Now call SecureSelectDG1 to attempt secure selection of DG1.
        //    SecureSelectDG1 secureSelectDG1 = new SecureSelectDG1(isoDep, secureMessaging);
        //    bool dg1Selected = await secureSelectDG1.SelectDG1Async();

        //    if (dg1Selected)
        //    {
        //        Console.WriteLine("📄 DG1 successfully selected!");
        //    }
        //    else
        //    {
        //        Console.WriteLine("❌ DG1 selection failed.");
        //        Console.WriteLine("Note: A 68 82 response may indicate that DG1 is not selectable via a SELECT command. " +
        //                          "In many ePassports DG files are read using READ BINARY commands instead.");
        //    }
        //}


        // EF.COM - FILE NOT FOUND
        //public static async Task StartPaceProtocol(IsoDep isoDep, string mrz, byte[] oid)
        //{
        //    var pace = new PaceProtocol(isoDep, mrz, oid);
        //    bool success = await pace.PerformPaceProtocol();

        //    if (success)
        //    {
        //        Console.WriteLine("✅ PACE authentication succeeded! Secure Messaging can now be established.");

        //        // Initialize Secure Messaging with the derived session keys.
        //        SecureMessaging secureMessaging = new SecureMessaging(pace.KSEnc, pace.KSMAC, SecureMessaging.ComputeSSC());

        //        // 🔹 Call Secure Select EF.COM after PACE is successful
        //        SecureSelectEFCom secureSelect = new SecureSelectEFCom(isoDep, secureMessaging);

        //        bool efComSelected = await secureSelect.SelectEFComAsync();
        //        if (efComSelected)
        //        {
        //            Console.WriteLine("📄 EF.COM successfully selected!");
        //        }
        //        else
        //        {
        //            Console.WriteLine("❌ EF.COM selection failed.");
        //        }

        //    }
        //    else
        //    {
        //        Console.WriteLine("❌ PACE authentication failed.");
        //    }
        //}


        private static bool OidEndsWith(byte[] oidBytes, string suffix)
        {
            string oidString = ConvertOidToString(oidBytes);
            return oidString.EndsWith(suffix);
        }

        // Select passport application
        private static async Task SelectApplication(IsoDep isoDep)
        {
            Console.WriteLine("<-SelectApplication->");
            try
            {
                isoDep.Connect();
                // isoDep.Timeout = 20000;
                Console.WriteLine("Starting SelectApplication!");
                Console.WriteLine($"IsoDep connected: {isoDep.IsConnected}");
                Console.WriteLine($"IsoDep timeout: {isoDep.Timeout}");

                byte[] selectApdu = new byte[] { 0x00, 0xA4, 0x04, 0x0C }
                    .Concat(new byte[] { (byte)AID_MRTD.Length })
                    .Concat(AID_MRTD)
                    .Concat(new byte[] { 0x00 })
                    .ToArray();

                Console.WriteLine($"Prepared SELECT APDU: {BitConverter.ToString(selectApdu)}");
                var response = await SendCommand(selectApdu, isoDep);

                if (response == null)
                {
                    Console.WriteLine("Received null response from SendCommand");
                    return;
                }

                if (!IsSuccessfulResponse(response))
                {
                    Console.WriteLine($"Invalid response: {BitConverter.ToString(response)}");
                    return;
                }

                Console.WriteLine("SelectApplication succeeded");
                Console.WriteLine("");
                Console.WriteLine("<---------------------------------------->");
                Console.WriteLine("");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception in SelectApplication: {ex.GetType().Name} - {ex.Message}");
            }
        }

        private static bool IsSuccessfulResponse(byte[] response)
        {
            Console.WriteLine("<-IsSuccessfulResponse->");
            if (response == null || response.Length < 2)
                return false;

            // Check the last two bytes for the status code
            return response[response.Length - 2] == 0x90 && response[response.Length - 1] == 0x00;
        }

        // Reading CardAccess
        private static async Task<byte[]> ReadCardAccess(IsoDep isoDep)
        {
            Console.WriteLine("<-ReadCardAccess->");
            try
            {
                Console.WriteLine("Selecting Master file...");
                byte[] command = new byte[] { 0x00, 0xA4, 0x00, 0x0C, 0x00, 0x3F, 0x00 };
                var response = await SendCommand(command, isoDep);

                if (IsSuccessfulResponse(response))
                {
                    Console.WriteLine($"Master file answer:{BitConverter.ToString(response)}");
                }
                Console.WriteLine("");
                Console.WriteLine("<---------------------------------------->");
                Console.WriteLine("");
                Console.WriteLine("Selecting CardAccess...");
                command = new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C };
                response = await SendCommand(command, isoDep);

                if (IsSuccessfulResponse(response))
                {
                    Console.WriteLine($"CardAccess answer:{BitConverter.ToString(response)}");
                }
                Console.WriteLine("");
                Console.WriteLine("<---------------------------------------->");
                Console.WriteLine("");
                Console.WriteLine("Reading CardAccess...");
                command = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x00 };
                response = await SendCommand(command, isoDep);

                if (IsSuccessfulResponse(response))
                {
                    Console.WriteLine($"CardAccess data::{BitConverter.ToString(response)}");
                    ParseCardAccessData(response);
                }
                return response;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error trying to read CardAccess: {ex.Message}");
                throw;
            }
        }

        private static bool IsErrorResponse(byte[] response)
        {
            if (response == null || response.Length < 2)
                return true;

            byte sw1 = response[response.Length - 2];
            byte sw2 = response[response.Length - 1];

            return sw1 == 0x69 || sw1 == 0x6A || sw1 == 0x6D;
        }

        // Method to parse Card Access Data
        public static void ParseCardAccessData(byte[] data)
        {
            Console.WriteLine("");
            Console.WriteLine("<---------------------------------------->");
            Console.WriteLine("");
            Console.WriteLine("<-ParseCardAccessData->");
            try
            {
                if (data.Length >= 2 && data[data.Length - 2] == 0x90 && data[data.Length - 1] == 0x00)
                {
                    data = data.Take(data.Length - 2).ToArray();
                }
                Console.WriteLine("______Raw Card Access Data");
                Console.WriteLine(BitConverter.ToString(data));
                Console.WriteLine("<------>");
                Console.WriteLine("");
                Console.WriteLine("");
                Console.WriteLine("______         Parsed Data         ______");

                int index = 0;
                // Outer sequence
                if (data[index++] == 0x31) // Sequence tag
                {
                    int outerLength = data[index++];
                    Console.WriteLine($"Outer Sequence Length: {outerLength}");
                    Console.WriteLine("<------>");
                    while (index < data.Length)
                    {
                        // PACEInfo sequence
                        if (data[index++] == 0x30) // Sequence tag
                        {
                            int sequenceLength = data[index++];
                            Console.WriteLine("______PACEInfo from EF.CardAccess");
                            Console.WriteLine($"Sequence Length: {sequenceLength}");

                            // OID
                            if (data[index++] == 0x06) // OID tag
                            {
                                int oidLength = data[index++];
                                byte[] oid = data.Skip(index).Take(oidLength).ToArray();
                                index += oidLength;
                                Console.WriteLine($"OID: {BitConverter.ToString(oid)}");
                            }

                            // Version
                            if (data[index++] == 0x02) // Integer tag
                            {
                                int versionLength = data[index++];
                                byte version = data[index++];
                                Console.WriteLine($"Version: {version}");
                            }

                            // Parameter ID
                            if (data[index++] == 0x02) // Integer tag
                            {
                                int paramLength = data[index++];
                                byte paramId = data[index++];
                                Console.WriteLine($"Parameter ID: 0x{paramId:X2}");
                            }
                            Console.WriteLine("<------>");
                        }
                    }
                }
                Console.WriteLine("______         End Parsed Data         ______");
                Console.WriteLine("");
                Console.WriteLine("<---------------------------------------->");
                Console.WriteLine("");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while parsing: {ex.Message}");
            }
        }

        // Helper method for sending commands
        public static async Task<byte[]> SendCommand(byte[] command, IsoDep isoDep)
        {
            Console.WriteLine("<-SendCommand->");
            try
            {
                Console.WriteLine($"Sending Command: {BitConverter.ToString(command)}");
                var response = isoDep.Transceive(command);
                if (response != null)
                {
                    Console.WriteLine($"Received Response: {BitConverter.ToString(response)}");
                }
                else
                {
                    Console.WriteLine("Received null response");
                }
                return response;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception in SendCommand: {ex.GetType().Name} - {ex.Message}");
                throw;
            }
        }

        public static List<byte[]> ValidateAndListPACEInfoWithDescriptions(byte[] cardAccessData)
        {
            Console.WriteLine("<-ValidateAndListPACEInfoWithDescriptions->");

            // Dictionary of valid OIDs and their descriptions
            var oidDescriptions = new Dictionary<string, string>
    {
        { "0.4.0.127.0.7.2.2.4.1.1", "id-PACE-DH-GM-3DES-CBC-CBC" },
        { "0.4.0.127.0.7.2.2.4.1.2", "id-PACE-DH-GM-AES-CBC-CMAC-128" },
        { "0.4.0.127.0.7.2.2.4.1.3", "id-PACE-DH-GM-AES-CBC-CMAC-192" },
        { "0.4.0.127.0.7.2.2.4.1.4", "id-PACE-DH-GM-AES-CBC-CMAC-256" },
        { "0.4.0.127.0.7.2.2.4.2.1", "id-PACE-ECDH-GM-3DES-CBC-CBC" },
        { "0.4.0.127.0.7.2.2.4.2.2", "id-PACE-ECDH-GM-AES-CBC-CMAC-128" },
        { "0.4.0.127.0.7.2.2.4.2.3", "id-PACE-ECDH-GM-AES-CBC-CMAC-192" },
        { "0.4.0.127.0.7.2.2.4.2.4", "id-PACE-ECDH-GM-AES-CBC-CMAC-256" },
        { "0.4.0.127.0.7.2.2.4.3.1", "id-PACE-DH-IM-3DES-CBC-CBC" },
        { "0.4.0.127.0.7.2.2.4.3.2", "id-PACE-DH-IM-AES-CBC-CMAC-128" },
        { "0.4.0.127.0.7.2.2.4.3.3", "id-PACE-DH-IM-AES-CBC-CMAC-192" },
        { "0.4.0.127.0.7.2.2.4.3.4", "id-PACE-DH-IM-AES-CBC-CMAC-256" },
        { "0.4.0.127.0.7.2.2.4.4.1", "id-PACE-ECDH-IM-3DES-CBC-CBC" },
        { "0.4.0.127.0.7.2.2.4.4.2", "id-PACE-ECDH-IM-AES-CBC-CMAC-128" },
        { "0.4.0.127.0.7.2.2.4.4.3", "id-PACE-ECDH-IM-AES-CBC-CMAC-192" },
        { "0.4.0.127.0.7.2.2.4.4.4", "id-PACE-ECDH-IM-AES-CBC-CMAC-256" },
        { "0.4.0.127.0.7.2.2.4.6.2", "id-PACE-ECDH-CAM-AES-CBC-CMAC-128" },
        { "0.4.0.127.0.7.2.2.4.6.3", "id-PACE-ECDH-CAM-AES-CBC-CMAC-192" },
        { "0.4.0.127.0.7.2.2.4.6.4", "id-PACE-ECDH-CAM-AES-CBC-CMAC-256" }
    };

            var results = new List<string>(); // To store valid OIDs with descriptions
            List<byte[]> oidByteList = new List<byte[]>();

            try
            {
                int index = 0;

                // Parse outer sequence
                if (cardAccessData[index++] == 0x31) // Sequence tag
                {
                    int outerLength = cardAccessData[index++];
                    Console.WriteLine($"______DoubleChecking length for this method");
                    Console.WriteLine($"Outer Sequence Length: {outerLength}");
                    Console.WriteLine($"");
                    while (index < cardAccessData.Length)
                    {
                        // Parse PACEInfo
                        if (cardAccessData[index++] == 0x30) // Sequence tag
                        {
                            int sequenceLength = cardAccessData[index++];

                            // Parse OID
                            if (cardAccessData[index++] == 0x06) // OID tag
                            {
                                int oidLength = cardAccessData[index++];
                                byte[] oidBytes = cardAccessData.Skip(index).Take(oidLength).ToArray();
                                oidByteList.Add(oidBytes);
                                index += oidLength;

                                // Convert OID to string
                                string oid = ConvertOidToString(oidBytes);
                                Console.WriteLine($"Found OID: {oid}");

                                // Check if the OID is valid and print description
                                if (oidDescriptions.TryGetValue(oid, out string description))
                                {
                                    string result = $"{oid} ({description})";
                                    results.Add(result);
                                    Console.WriteLine($"Valid OID found: {result}");
                                    Console.WriteLine($"");
                                }
                                else
                                {
                                    Console.WriteLine($"OID is not valid: {oid}");
                                }
                            }

                            // Skip other data (Version and Parameter ID)
                            index += 4; // Skip Version and Parameter ID
                        }
                    }
                }

                if (results.Count == 0)
                {
                    throw new PaceException("No valid PACE OID found in CardAccess data.");
                }

                return oidByteList; // Return all valid OIDs with descriptions
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during PACEInfo validation: {ex.Message}");
                throw;
            }
        }

        // ------------------- Fel, måste fixas, kolla headern och Le, sida 91 ICAO p11.
        private static async Task<byte[]> ReadEfComFile(IsoDep isoDep, SecureMessaging secureMessaging)
        {
            Console.WriteLine("Reading EF.COM file...");

            // Construct a READ BINARY command for EF.COM.
            // Adjust the header based on your file selection – EF.COM’s file identifier is typically known.
            // Here we assume a header similar to: [CLA, INS, P1, P2] = {0x0C, 0xB0, 0x00, 0x00}
            byte[] readEfComHeader = new byte[] { 0x0C, 0xB0, 0x00, 0x00 };

            // Use an Le of 0x00, indicating extended length or that the length is embedded in the TLV structure.
            byte[] le = new byte[] { 0x00 };

            // Protect the APDU using your secure messaging instance.
            byte[] secureApdu = secureMessaging.ProtectCommand(readEfComHeader, null, le);
            Console.WriteLine($"Sending protected EF.COM APDU: {BitConverter.ToString(secureApdu)}");

            // Transceive the APDU.
            byte[] response = await isoDep.TransceiveAsync(secureApdu);
            Console.WriteLine($"Received EF.COM response: {BitConverter.ToString(response)}");

            // Unprotect the response to obtain the clear EF.COM data.
            byte[] efComData = secureMessaging.UnprotectResponse(response);
            Console.WriteLine($"Decrypted EF.COM Data: {BitConverter.ToString(efComData)}");

            return efComData;
        }

        // Helper to convert OID bytes to string
        private static string ConvertOidToString(byte[] oidBytes)
        {
            var oid = new List<string>();
            oid.Add((oidBytes[0] / 40).ToString());
            oid.Add((oidBytes[0] % 40).ToString());
            long value = 0;

            for (int i = 1; i < oidBytes.Length; i++)
            {
                value = (value << 7) | (oidBytes[i] & 0x7F);
                if ((oidBytes[i] & 0x80) == 0)
                {
                    oid.Add(value.ToString());
                    value = 0;
                }
            }
            return string.Join(".", oid);
        }

    }

    // Custom exceptions for pace
    public class PaceException : Exception
    {
        public PaceException(string message) : base(message) { }
        public PaceException(string message, Exception inner) : base(message, inner) { }
    }
}
