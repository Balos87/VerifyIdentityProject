using Android.Nfc.Tech;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
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
                // var paceInfo = ParsePaceInfo(cardAccess);

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
                                Console.WriteLine($"Protocol ID: {BitConverter.ToString(oid)}");
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
                Console.WriteLine("______         End Data         ______");
                Console.WriteLine("");
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

    }

    // Custom exceptions for pace
    public class PaceException : Exception
    {
        public PaceException(string message) : base(message) { }
        public PaceException(string message, Exception inner) : base(message, inner) { }
    }
}
