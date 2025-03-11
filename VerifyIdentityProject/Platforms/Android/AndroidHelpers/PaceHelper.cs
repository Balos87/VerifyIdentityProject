using Android.Nfc.Tech;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using VerifyIdentityProject.Helpers;

namespace VerifyIdentityProject.Platforms.Android.AndroidHelpers
{
    public class PaceHelper
    {
        private readonly IsoDep _isoDep;
        private static byte[] AID_MRTD = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
        private static Dictionary<string, string> _mrz;
        public PaceHelper(IsoDep isoDep)
        {
            _isoDep = isoDep;
        }

        // Select passport application
        public static void SelectApplicationPace(IsoDep isoDep)
        {
            //Console.WriteLine("<-SelectApplication->");
            try
            {
                isoDep.Connect();
                Console.WriteLine("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");
                Console.WriteLine("👉🏽Starting SelectApplication!");
                Console.WriteLine($"IsoDep connected: {isoDep.IsConnected}");
                Console.WriteLine($"IsoDep timeout: {isoDep.Timeout}");

                byte[] selectApdu = new byte[] { 0x00, 0xA4, 0x04, 0x0C }
                    .Concat(new byte[] { (byte)AID_MRTD.Length })
                    .Concat(AID_MRTD)
                    .Concat(new byte[] { 0x00 })
                    .ToArray();

                //Console.WriteLine($"Prepared SELECT APDU: {BitConverter.ToString(selectApdu)}");
                var response = SendCommandPace(selectApdu, isoDep);

                if (response == null)
                {
                    Console.WriteLine("Received null response from SendCommand");
                    return;
                }

                if (!SecureMessagingHelper.IsSuccessfulResponsePace(response))
                {
                    Console.WriteLine($"Invalid response: {BitConverter.ToString(response)}");
                    return;
                }

                Console.WriteLine("SelectApplication succeeded");
                Console.WriteLine("");
                Console.WriteLine("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");
                Console.WriteLine("");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception in SelectApplication: {ex.GetType().Name} - {ex.Message}");
            }
        }

        // Reading CardAccess
        public static byte[] ReadCardAccessPace(IsoDep isoDep)
        {
            //Console.WriteLine("<-ReadCardAccess->");
            try
            {
                Console.WriteLine("👉🏽Selecting Master file...");
                byte[] command = new byte[] { 0x00, 0xA4, 0x00, 0x0C, 0x00, 0x3F, 0x00 };
                var response = SendCommandPace(command, isoDep);

                if (SecureMessagingHelper.IsSuccessfulResponsePace(response))
                {
                    //Console.WriteLine($"Master file answer:{BitConverter.ToString(response)}");
                }
                Console.WriteLine("");
                Console.WriteLine("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");
                Console.WriteLine("");
                Console.WriteLine("👉🏽Selecting CardAccess...");
                command = new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C };
                response = SendCommandPace(command, isoDep);

                if (SecureMessagingHelper.IsSuccessfulResponsePace(response))
                {
                    //Console.WriteLine($"CardAccess answer:{BitConverter.ToString(response)}");
                }
                Console.WriteLine("");
                Console.WriteLine("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");
                Console.WriteLine("");
                Console.WriteLine("👉🏽Reading CardAccess...");
                command = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x00 };
                response = SendCommandPace(command, isoDep);

                if (SecureMessagingHelper.IsSuccessfulResponsePace(response))
                {
                    //Console.WriteLine($"CardAccess data::{BitConverter.ToString(response)}");
                    ParseCardAccessDataPace(response);
                }
                return response;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error trying to read CardAccess: {ex.Message}");
                throw;
            }
        }

        // Method to parse Card Access Data
        public static void ParseCardAccessDataPace(byte[] data)
        {
            //Console.WriteLine("\n<---------------------------------------->\n");
            // Console.WriteLine("<-ParseCardAccessData->");
            try
            {
                if (data.Length >= 2 && data[data.Length - 2] == 0x90 && data[data.Length - 1] == 0x00)
                {
                    data = data.Take(data.Length - 2).ToArray();
                }
                // Console.WriteLine("Raw Card Access Data");
                // Console.WriteLine(BitConverter.ToString(data));
                // Console.WriteLine("<------>\n\n");
                Console.WriteLine("\n➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");
                Console.WriteLine("➖➖➖➖➖➖➖Parsed Data➖➖➖➖➖➖");

                int index = 0;
                // Outer sequence
                if (data[index++] == 0x31) // Sequence tag
                {
                    int outerLength = data[index++];
                    // Console.WriteLine($"Outer Sequence Length: {outerLength}");
                    // Console.WriteLine("<------>");
                    while (index < data.Length)
                    {
                        // PACEInfo sequence
                        if (data[index++] == 0x30) // Sequence tag
                        {
                            int sequenceLength = data[index++];
                            Console.WriteLine("PaceInfo from EF.CardAccess");
                            //Console.WriteLine($"Sequence Length: {sequenceLength}");

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
                            Console.WriteLine("\n");
                        }
                    }
                }
                Console.WriteLine("➖➖➖➖➖➖End Parsed Data➖➖➖➖➖➖");
                Console.WriteLine("\n➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖\n");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error while parsing: {ex.Message}");
            }
        }

        // Helper method for sending commands
        public static byte[] SendCommandPace(byte[] command, IsoDep isoDep)
        {
            //Console.WriteLine("<-SendCommand->");
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

        public static List<byte[]> ValidateAndListPACEInfoWithDescriptionsPace(byte[] cardAccessData)
        {
           // Console.WriteLine("<-ValidateAndListPACEInfoWithDescriptions->");

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
                    // Console.WriteLine($"______DoubleChecking length for this method");
                    // Console.WriteLine($"Outer Sequence Length: {outerLength}");
                    // Console.WriteLine($"");
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
                                string oid = OidHelper.ConvertOidToString(oidBytes);
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

    }
}
