using Android.Nfc.Tech;
using VerifyIdentityProject.Helpers;

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
        public static byte[] PerformPace(IsoDep isoDep)
        {
            Console.WriteLine("<-PerformPace->");
            try
            {
                // Step 0: Select the passport application
                SelectApplication(isoDep);

                // Step 1: Read CardAccess to get PACE parameters
                var cardAccess = ReadCardAccess(isoDep);
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

                        var pace = new PaceProtocol(isoDep, mrzData, oid);
                        bool success = pace.PerformPaceProtocol();
                        Console.WriteLine(success ? "PACE-authentication succeeded!" : "PACE-authentication failed");

                        var (KSEnc, KSMac) = pace.GetKsEncAndKsMac();

                        var secureMessage = new SecureMessage(KSEnc, KSMac, isoDep);
                        bool secureMessageSuccess = secureMessage.PerformSecureMessage();
                        Console.WriteLine(secureMessageSuccess ? "Secure Message succeeded!" : "Secure Message failed");

                    }
                }
                Console.WriteLine("");
                Console.WriteLine("<---------------------------------------->");


                return cardAccess;
            }
            catch (Exception ex)
            {
                throw new PaceException("The PACE process failed", ex);
            }
        }

        private static bool OidEndsWith(byte[] oidBytes, string suffix)
        {
            string oidString = ConvertOidToString(oidBytes);
            return oidString.EndsWith(suffix);
        }

        // Select passport application
        private static void SelectApplication(IsoDep isoDep)
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
                var response = SendCommand(selectApdu, isoDep);

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
        private static byte[] ReadCardAccess(IsoDep isoDep)
        {
            Console.WriteLine("<-ReadCardAccess->");
            try
            {
                Console.WriteLine("Selecting Master file...");
                byte[] command = new byte[] { 0x00, 0xA4, 0x00, 0x0C, 0x00, 0x3F, 0x00 };
                var response = SendCommand(command, isoDep);

                if (IsSuccessfulResponse(response))
                {
                    Console.WriteLine($"Master file answer:{BitConverter.ToString(response)}");
                }
                Console.WriteLine("");
                Console.WriteLine("<---------------------------------------->");
                Console.WriteLine("");
                Console.WriteLine("Selecting CardAccess...");
                command = new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C };
                response = SendCommand(command, isoDep);

                if (IsSuccessfulResponse(response))
                {
                    Console.WriteLine($"CardAccess answer:{BitConverter.ToString(response)}");
                }
                Console.WriteLine("");
                Console.WriteLine("<---------------------------------------->");
                Console.WriteLine("");
                Console.WriteLine("Reading CardAccess...");
                command = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x00 };
                response = SendCommand(command, isoDep);

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
        public static byte[] SendCommand(byte[] command, IsoDep isoDep)
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
