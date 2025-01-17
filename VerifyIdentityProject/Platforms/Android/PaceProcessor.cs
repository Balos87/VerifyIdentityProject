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

        // Konstruktor
        public PaceProcessor(IsoDep isoDep)
        {
            _isoDep = isoDep;
        }

        // Huvudmetod för att köra PACE
        public static async Task<byte[]> PerformPace(IsoDep isoDep)
        {
            try
            {
                // Steg 0: Välj passport application
                await SelectApplication(isoDep);

                // Steg 1: Läs CardAccess för att få PACE-parametrar
                var cardAccess = await ReadCardAccess(isoDep);
                //var paceInfo = ParsePaceInfo(cardAccess);

                //// Steg 2: MSE:Set AT kommando för att starta PACE
                //await InitializePace(paceInfo);

                //// Steg 3: Få krypterat nonce från passet
                //var encryptedNonce = await GetEncryptedNonce();

                //// Steg 4: Dekryptera nonce med lösenord från MRZ
                //var password = DerivePasswordFromMrz(mrz);
                //var decryptedNonce = DecryptNonce(encryptedNonce, password);

                //// Steg 5: Generera och utbyt efemära nycklar
                //var mappingData = await PerformMapping(decryptedNonce);
                //var (myKeyPair, theirPubKey) = await ExchangeEphemeralKeys(mappingData);

                //// Steg 6: Beräkna gemensam hemlighet
                //var sharedSecret = CalculateSharedSecret(myKeyPair, theirPubKey);
                byte[] sharedSecret = null;
                // Steg 7: Härleda sessionsnycklar
                //var (KSenc, KSmac) = DeriveSessionKeys(sharedSecret);

                // Steg 8: Utför Mutual Authentication
                // await PerformMutualAuthentication(KSenc, KSmac);

                return cardAccess;
            }
            catch (Exception ex)
            {
                throw new PaceException("PACE-processen misslyckades", ex);
            }
        }

        // Välj passport application
        private static async Task SelectApplication(IsoDep isoDep)
        {
            try
            {
                isoDep.Connect();
                //isoDep.Timeout = 20000;
                Console.WriteLine("Börjar SelectApplication");
                Console.WriteLine($"IsoDep anslutet: {isoDep.IsConnected}");
                Console.WriteLine($"IsoDep timeout: {isoDep.Timeout}");

                byte[] selectApdu = new byte[] { 0x00, 0xA4, 0x04, 0x0C }
                    .Concat(new byte[] { (byte)AID_MRTD.Length })
                    .Concat(AID_MRTD)
                    .Concat(new byte[] { 0x00 })
                    .ToArray();

                Console.WriteLine($"Förberedd SELECT APDU: {BitConverter.ToString(selectApdu)}");
                var response = await SendCommand(selectApdu, isoDep);

                Console.WriteLine("Kommando skickat, kontrollerar svar");

                if (response == null)
                {
                    Console.WriteLine("Fick null-svar från SendCommand");
                    return; // Eller hantera det på annat sätt
                }

                if (!IsSuccessfulResponse(response))
                {
                    Console.WriteLine($"Ogiltigt svar: {BitConverter.ToString(response)}");
                    return; // Eller hantera det på annat sätt
                }

                Console.WriteLine("SelectApplication lyckades");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception i SelectApplication: {ex.GetType().Name} - {ex.Message}");
                // Du kanske vill hantera felet här istället för att kasta vidare
            }
        }

        // Kontrollera också din IsSuccessfulResponse-metod
        private static bool IsSuccessfulResponse(byte[] response)
        {
            if (response == null || response.Length < 2)
                return false;

            // Kontrollera de sista två byten för statuskoden
            return response[response.Length - 2] == 0x90 && response[response.Length - 1] == 0x00;
        }

        // Läs CardAccess fil
        private static async Task<byte[]> ReadCardAccess(IsoDep isoDep)
        {
            try
            {
                Console.WriteLine("Selecting Master file...");
                byte[] command = new byte[] { 0x00, 0xA4, 0x00, 0x0C, 0x00, 0x3F, 0x00 };
                var response = await SendCommand(command, isoDep);

                if (IsSuccessfulResponse(response))
                {
                    Console.WriteLine($"Master file answer:{BitConverter.ToString(response)}");
                }

                Console.WriteLine("Selecting CardAccess...");
                command = new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C };
                response = await SendCommand(command, isoDep);

                if (IsSuccessfulResponse(response))
                {
                    Console.WriteLine($"CardAccess answer:{BitConverter.ToString(response)}");
                }
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
                Console.WriteLine($"Fel vid läsning av CardAccess: {ex.Message}");
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
        public static void ParseCardAccessData(byte[] data)
        {
            try
            {
                if (data.Length >= 2 && data[data.Length - 2] == 0x90 && data[data.Length - 1] == 0x00)
                {
                    data = data.Take(data.Length - 2).ToArray();
                }

                Console.WriteLine("Raw Card Access Data:");
                Console.WriteLine(BitConverter.ToString(data));
                Console.WriteLine("\nParsed Data:");

                int index = 0;
                // Outer sequence
                if (data[index++] == 0x31) // Sequence tag
                {
                    int outerLength = data[index++];
                    Console.WriteLine($"Outer Sequence Length: {outerLength}");

                    while (index < data.Length)
                    {
                        // PACEInfo sequence
                        if (data[index++] == 0x30) // Sequence tag
                        {
                            int sequenceLength = data[index++];
                            Console.WriteLine("\nPACEInfo:");
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
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid tolkning: {ex.Message}");
            }
        }


        // Hjälpmetod för att skicka kommandon
        public static async Task<byte[]> SendCommand(byte[] command, IsoDep isoDep)
        {
            try
            {
                Console.WriteLine($"Försöker skicka kommando: {BitConverter.ToString(command)}");
                var response = isoDep.Transceive(command);
                if (response != null)
                {
                    Console.WriteLine($"Fick svar: {BitConverter.ToString(response)}");
                }
                else
                {
                    Console.WriteLine($"Fick svar: {BitConverter.ToString(response)}");
                }
                return response;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception i SendCommand: {ex.GetType().Name} - {ex.Message}");
                throw; // Kasta om undantaget för att behålla stack trace
            }
        }
    }

    // Custom exception för PACE-fel
    public class PaceException : Exception
    {
        public PaceException(string message) : base(message) { }
        public PaceException(string message, Exception inner) : base(message, inner) { }
    }
}
