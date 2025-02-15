using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Android.Nfc.Tech;
using Android.Health.Connect.DataTypes.Units;
using static Android.Renderscripts.ScriptGroup;
using System.Numerics;
using System.Diagnostics;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Asn1.Sec;
using System;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Utilities.Encoders;

namespace VerifyIdentityProject.Platforms.Android
{
    public class PaceProtocol
    {
        private readonly IsoDep isoDep;
        private byte[] sessionKey;
        private byte[] oid;
        private readonly string mrz;
        private Org.BouncyCastle.Math.EC.ECPoint mappedPoint;  // Från Map response
        private Org.BouncyCastle.Math.EC.ECPoint sharedSecret; // Från Key exchange
        private AsymmetricKeyParameter privateKey;
        private ECPrivateKeyParameters privateKeyParameters;
        private Org.BouncyCastle.Math.EC.ECPoint ourPublicKey;        // Vår publika nyckel från Key Agreement (steg 3)
        private Org.BouncyCastle.Math.EC.ECPoint theirPublicKey;      // Deras publika nyckel från Key Agreement (steg 3)
        private byte[] KSMAC;
        private byte[] KSENC;

        public PaceProtocol(IsoDep isoDep, string mrz, byte[]oid)
        {
            this.isoDep = isoDep;
            this.mrz = mrz;
            this.oid = oid;
        }

        public async Task<bool> PerformPaceProtocol()
        {
            isoDep.Timeout = 400000;
            try
            {
                // 1. MSE:SET AT
                if (!await MseSetAtSelectPaceProtocol())
                    return false;

                // 2. Få krypterad nonce
                var encryptedNonce = await GetEncryptedNonce();
                if (encryptedNonce == null)
                    return false;

                //var decyptnonse = PaceHelper.DecryptNonce(encryptedNonce, mrz);
                //Tested with dokument mrz and encryptedNonce and I got the same result as in the document ✅
                //[DOTNET] DecryptNonce: 3F-00-C4-D3-9D-15-3F-2B-2A-21-4A-07-8D-89-9B-22
                // 3. Dekryptera nonce
                var decryptedNonce = DecryptNonce(encryptedNonce);

                // 4. Generera och skicka mappade parametrar
                var mappedParams = await GenerateAndSendMappedParameters(decryptedNonce);
                if (!mappedParams)
                    return false;

                
                // 5. Utför ECDH nyckelutbyte
                if (!await PerformKeyExchange())
                    return false;

                // 6. Verifiera autentiseringstoken
                return await VerifyAuthenticationToken();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"PACE-protokoll misslyckades: {ex.Message}");
                
                return false;
            }
        }
       
        private async Task<bool> MseSetAtSelectPaceProtocol()
        {
            // Protocoll OID
            //byte[] protocolOID = new byte[] { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04 };
            byte[] protocolOID = oid;

            // Bygg MSE:SET AT kommandot
            List<byte> command = new List<byte>
            {
                0x00,    // CLA 
                0x22,    // INS (MANAGE SECURITY ENVIRONMENT)
                0xC1,    // P1
                0xA4,    // P2 (Set Authentication Template)
                0x00,    // Lc (length, will be updated later)
                0x80,    // Tag for kryptographic mechanism
                (byte)protocolOID.Length  // OID length
            };

            // Lägg till OID
            command.AddRange(protocolOID);

            // Password reference (0x83 tag)
            command.AddRange(new byte[]
            {
                0x83,    // Tag for password reference
                0x01,    // Length of value
                0x01     // Value: 0x01 for MRZ
            });

            // Lägg till domain parameters reference (0x84 tag)
            command.AddRange(new byte[]
            {
                0x84,    // Tag for domain parameters
                0x01,    // Length of value
                0x10     // Parameter ID 
            });

            // Uppdating Lc (total length of data)
            command[4] = (byte)(command.Count - 5);

            byte[] finalCommand = command.ToArray();
            Console.WriteLine($"mseSetAtCommand: {BitConverter.ToString(finalCommand)}");

            var response = isoDep.Transceive(finalCommand);
            Console.WriteLine($"response: {BitConverter.ToString(response)}");

            return IsSuccessful(response);
        }

        private async Task<byte[]> GetEncryptedNonce()
        {
            Console.WriteLine("-------------------------------------------------------- GetEncryptedNonce started...");
            var getNonceCommand = new byte[]
            {
                0x10,    // CLA (command chaining)
                0x86,    // INS
                0x00,    // P1
                0x00,    // P2
                0x02,    // Lc
                0x7C,    // Dynamic Authentication Data
                0x00,    // Tom data
                0x00     // Le (förväntat svar, sätter till 0x00 för att få längdindikation)
            };
            Console.WriteLine($"Sending getNonceCommand: {BitConverter.ToString(getNonceCommand)}");
            Stopwatch sw = new Stopwatch();
            sw.Start();
            Console.WriteLine("timer started...");

            var response = await isoDep.TransceiveAsync(getNonceCommand);
            sw.Stop();
            Console.WriteLine("timer stopped...");
            Console.WriteLine("Total time:" + sw.Elapsed.TotalSeconds.ToString());
            Console.WriteLine($"GetEncryptedNonce response: {BitConverter.ToString(response)}");
            if (!IsSuccessful(response))
                return null;


            return ParseEncryptedNonce(response);
        }

        // Hjälpmetod för att extrahera nonce från svar
        private byte[] ParseEncryptedNonce(byte[] response)
        {
            Console.WriteLine("-------------------------------------------------------- ParseEncryptedNonce started...");
            try
            {
                // Ta bort status bytes (90 00)
                var data = response.Take(response.Length - 2).ToArray();

                // Kontrollera outer tag (7C)
                if (data[0] != 0x7C)
                    throw new Exception("Ogiltig outer tag i nonce svar");

                // Skippa outer tag och längd
                int index = 2;

                // Hitta nonce tag (80)
                if (data[index] != 0x80)
                    throw new Exception("Kunde inte hitta nonce tag (80)");

                // Läs nonce längd
                int nonceLength = data[index + 1];

                // Extrahera själva nonce datan
                byte[] nonce = new byte[nonceLength];
                Array.Copy(data, index + 2, nonce, 0, nonceLength);

                Console.WriteLine($"Extraherad nonce längd: {nonceLength}");
                Console.WriteLine($"Extraherad nonce: {BitConverter.ToString(nonce)}");

                return nonce;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fel vid parsing av nonce: {ex.Message}");
                return null;
            }
        }

        //Tested with dokument mrz and encryptedNonce and I got the same result as in the document ✅
        //[DOTNET] DecryptNonce: 3F-00-C4-D3-9D-15-3F-2B-2A-21-4A-07-8D-89-9B-22
        private byte[] DecryptNonce(byte[] encryptedNonce)
        {
            Console.WriteLine("-------------------------------------------------------- DecryptNonce started...");

            using (var sha1 = SHA1.Create())
            {
                //Tested with dokument mrz and I got the same result -Kpi- as in the document ✅
                var kPi = CalculateKPiFromMrz(mrz);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = kPi;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.None;
                    aes.IV = new byte[16];

                    using (var decryptor = aes.CreateDecryptor())
                    {
                        var decryptedNonce = decryptor.TransformFinalBlock(encryptedNonce, 0, encryptedNonce.Length);
                        Console.WriteLine($"DecryptNonce: {BitConverter.ToString(decryptedNonce)}");
                        return decryptedNonce;
                    }
                }
            }
        }

        // Calculate KPi from K
        private byte[] CalculateKPiFromMrz(string mrzData)
        {
            Console.WriteLine("-------------------------------------------------------- Calculate KPi From Mrz started...");

            string mrzData2 = "35897577<390091982606152";
            //Calculate K from MRZ
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(mrzData);
                byte[] k = sha1.ComputeHash(inputBytes);
                //Tested with dokument mrz and I got the same result -K- as in the document ✅
                //[DOTNET] Output k as hex: 7E-2D-2A-41-C7-4E-A0-B3-8C-D3-6F-86-39-39-BF-A8-E9-03-2A-AD
                Console.WriteLine($"Output k as hex: {BitConverter.ToString(k)}");

                // Calculate KPi from K
                var KPi = CalculateKPi(k);
                Console.WriteLine("-------------------------------------------------------- Calculate KPi From Mrz finished...");
                return KPi;
            }
        }
        public static byte[] CalculateKPi(byte[] k)
        {
            // Counter value 3 as big-endian bytes
            byte[] counter = BitConverter.GetBytes(3);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counter);
            }

            Console.WriteLine($"Counter bytes: {BitConverter.ToString(counter)}");

            // Concatenate K with counter
            byte[] combined = new byte[k.Length + counter.Length];
            k.CopyTo(combined, 0);
            counter.CopyTo(combined, k.Length);

            Console.WriteLine($"Combined input for KDF: {BitConverter.ToString(combined)}");

            //// Calculate SHA-1 hash
            //using (SHA1 sha1 = SHA1.Create())
            //{
            //    byte[] fullHash = sha1.ComputeHash(combined);
            //    Console.WriteLine($"Full SHA-1 hash: {BitConverter.ToString(fullHash)}");

            //    // Take first 16 bytes for Kπ
            //    byte[] kPi = new byte[16];
            //    Array.Copy(fullHash, kPi, 16);
            //    //Tested with dokument mrz and I got the same result -KPi- as in the document ✅
            //    //[DOTNET] Final Kπ (first 16 bytes): 89-DE-D1-B2-66-24-EC-1E-63-4C-19-89-30-28-49-DD
            //    Console.WriteLine($"Final Kπ (first 16 bytes): {BitConverter.ToString(kPi)}");
            //    return kPi;
            //}

            // Calculate SHA-256 hash
            using (var sha256 = SHA256.Create())
            {
                byte[] fullHash = sha256.ComputeHash(combined);
                Console.WriteLine($"Full SHA-256 hash output: {BitConverter.ToString(fullHash)}");

                // Ta första 32 bytes för 256-bit AES nyckel
                byte[] kPi = new byte[32];
                Array.Copy(fullHash, kPi, 32);

                Console.WriteLine($"Final Kπ (32 bytes): {BitConverter.ToString(kPi)}");
                return kPi;
            }
        }

        private async Task<bool> GenerateAndSendMappedParameters(byte[] decryptedNonce)
        {
            Console.WriteLine("-------------------------------------------------------- GenerateAndSendMappedParameters started...");
            try
            {
                var curve = TeleTrusTNamedCurves.GetByName("brainpoolP384r1");
                var curveParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
                //--------------------------------------------------------------------------------skapar publik nyckel med nya metoden
                var keyGenerator = new ECDHKeyGenerator(curveParams);

                // Generera nyckelpar - Gått igenom och den borde vara ok ✅
                var keyPair = keyGenerator.GenerateKeyPair();

                // Konvertera publik nyckel till byte array (för att skicka till chip) - Gått igenom och den borde vara ok ✅
                byte[] publicKeyBytes = ECDHKeyGenerator.PublicKeyToBytes(keyPair.PublicKey);
                Console.WriteLine($"publicKeyBytes: {BitConverter.ToString(publicKeyBytes)}");

                // Skapa APDU för att skicka vår publika nyckel - Gått igenom och den följer TLV som dokumentation ✅
                var ourPublicKeyApdu = ECDHKeyGenerator.BuildMapNonceCommand(publicKeyBytes);
                Console.WriteLine($"Sending ourPublicKey: {BitConverter.ToString(ourPublicKeyApdu)}");

                // Skicka vår publika nyckel och få chippets publika nyckel - Gått igenom och den följer TLV som dokumentation ✅
                var chipPublicKey = await isoDep.TransceiveAsync(ourPublicKeyApdu);
                Console.WriteLine($"Recieved chipPublicKey: {BitConverter.ToString(chipPublicKey)}");

                // Extrahera chippets publika nyckel från svaret - Gått igenom och den tar bort TLV strukturen. behåller 04||x||y ✅
                var exractedChipPublicKey = ECDHKeyGenerator.ExtractPublicKeyFromResponse(chipPublicKey);
                Console.WriteLine($"exractedChipPublicKey: {BitConverter.ToString(exractedChipPublicKey)}");

                // Räknar ut H med hjälp av vår privata nyckel och chippets publika nyckel och curveParams
                var H = ECDHKeyGenerator.CalculateH(curveParams, keyPair.PrivateKey, exractedChipPublicKey);
                Console.WriteLine($"Calculated H: {BitConverter.ToString(H.GetEncoded(false))}");
                if (!H.IsValid())
                    throw new Exception("Fel: H är inte en giltig punkt på kurvan!");

                // Skapa BigInteger från decryptedNonce
                var bigIntegerS = ECDHKeyGenerator.SToBigInteger(decryptedNonce, curveParams);
                Console.WriteLine($"bigInteger(s): {bigIntegerS.ToString(16)}");


                // Beräkna gTilde med hjälp av curvparams.G och s och H
                var gTilde = curveParams.G.Multiply(bigIntegerS).Add(H).Normalize();

                if (!gTilde.IsValid())
                    throw new Exception("Fel: gTilde är inte en giltig punkt på kurvan!");

                //Skapa nyckelpar med våran gTilde
                var gTildeKeys = keyGenerator.GenerateKeyPairWithGTilde(gTilde);
                Console.WriteLine($"gTildeKeys.PrivatKEy: {gTildeKeys.PrivateKey}");


                // Konvertera vår gTilde-publika nyckel till byte array
                byte[] gTildePublicKeyBytes = ECDHKeyGenerator.PublicKeyToBytes(gTildeKeys.PublicKey);
                Console.WriteLine($"gTildePublicKeyBytes: {gTildePublicKeyBytes}");


                // Skapa APDU för att skicka vår gTilde-publika nyckel
                var gTildePublicKeyAPdu = ECDHKeyGenerator.BuildKeyAgreementCommandGTilde(gTildePublicKeyBytes);

                Console.WriteLine($"Sending gTildePublicKeyAPdu: {BitConverter.ToString(gTildePublicKeyAPdu)}");
                // Skicka vår gTilde-publika nyckel och få chippets-gTilde-publika nyckel
                var chipGTildePublicKey = await isoDep.TransceiveAsync(gTildePublicKeyAPdu);
                Console.WriteLine($"Recieved chipGTildePublicKey: {BitConverter.ToString(chipGTildePublicKey)}");

                // Extrahera chippets gTilde-publika nyckel från svaret
                var extractedChipGTildePublicKey = ECDHKeyGenerator.ExtractGTildePublicKeyFromResponse(chipGTildePublicKey);
                Console.WriteLine($"extractedChipGTildePublicKey: {BitConverter.ToString(extractedChipGTildePublicKey)}");

                // Konvertera chippets publika nyckel bytes till ECPoint
                Org.BouncyCastle.Math.EC.ECPoint chipGTildePublicKeyDecoded = curveParams.Curve.DecodePoint(extractedChipGTildePublicKey);
                Console.WriteLine($"chipGTildePublicKeyDecoded: X:{chipGTildePublicKeyDecoded.XCoord} Y:{chipGTildePublicKeyDecoded.YCoord}");


                // Jämför om punkterna är lika. Vår publik key och chippets publik key får inte vara samma
                if (gTildeKeys.PublicKey.Equals(chipGTildePublicKeyDecoded))
                    throw new Exception("Public keys are identical - security violation!");


                // Multiplicera med vår gTilde-privata nyckel för att få K
                Org.BouncyCastle.Math.EC.ECPoint K = chipGTildePublicKeyDecoded.Multiply(gTildeKeys.PrivateKey).Normalize();
                if (!K.IsValid())
                    throw new Exception("Fel: gTilde är inte en giltig punkt på kurvan!");

                Console.WriteLine($"Calculated K: {BitConverter.ToString(K.GetEncoded(false))}");


                // Sedan använder vi K för att härleda KSMac och KSEnc nycklarna:
                byte[] KSEnc = ECDHKeyGenerator.DeriveKeyFromK(K, 1);  // Krypteringsnyckel
                byte[] KSMAC = ECDHKeyGenerator.DeriveKeyFromK(K, 2);  // Autentiseringsnyckel

                Console.WriteLine($"KSEnc: {BitConverter.ToString(KSEnc)}");
                Console.WriteLine($"KSMAC: {BitConverter.ToString(KSMAC)}");

                //Sätter ihop en MSE:SET AT kommando som ska innehålla publika nyckeln och OID
                //jämförde med dokumentets inputData och jag har samma format som i dokumentet ✅
                var inputDataForTPCD = ECDHKeyGenerator.BuildAuthenticationTokenInput(extractedChipGTildePublicKey, oid);
                var inputDataForTIC = ECDHKeyGenerator.BuildAuthenticationTokenInput(gTildePublicKeyBytes, oid);
                Console.WriteLine($"inputDataForTPCD: {BitConverter.ToString(inputDataForTPCD)}");
                Console.WriteLine($"inputDataForTIC: {BitConverter.ToString(inputDataForTIC)}");

                // Beräkna autentiserings token för TPCD och TIC. Vi använder KSMAC och "kommandot" vi satte ihop förra steget för att räkna ut token
                //Testade med dokumentets KsMac och inputData och jag fick samma svar som i dokumentet ✅
                var TPCD = ECDHKeyGenerator.CalculateAuthenticationToken(KSMAC, inputDataForTPCD);
                var TIC = ECDHKeyGenerator.CalculateAuthenticationToken(KSMAC, inputDataForTIC);
                Console.WriteLine($"TPCD: {BitConverter.ToString(TPCD)}");
                Console.WriteLine($"TIC: {BitConverter.ToString(TIC)}");

                //Bygger kommandot för att skicka TPCD till chipet
                var comand = ECDHKeyGenerator.BuildTokenCommand(TPCD);
                Console.WriteLine($"sending TPCD command: {BitConverter.ToString(comand)}");

                var responseTic = await isoDep.TransceiveAsync(comand);
                Console.WriteLine($"responseTic respo: {BitConverter.ToString(responseTic)}");



                return IsSuccessful(chipGTildePublicKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false;
            }
        }


        private static byte[] ParseTLV(byte[] data, byte expectedTag)
        {
            try
            {
                int index = 0;
                while (index < data.Length - 1)  // -1 för att säkerställa att vi har plats för längdbyte
                {
                    // Kontrollera för strukturerade taggar (7C, etc.)
                    byte tag = data[index++];
                    if (tag == 0x7C)  // Om det är en strukturerad tagg
                    {
                        // Få längden på den strukturerade taggen
                        int structLength = data[index++];
                        // Fortsätt söka inom den strukturerade taggen
                        byte[] innerData = new byte[structLength];
                        Array.Copy(data, index, innerData, 0, structLength);
                        return ParseTLV(innerData, expectedTag);
                    }

                    // Hantera längden
                    int length = data[index++];
                    if (length > 0x80)
                    {
                        int numberOfLengthBytes = length - 0x80;
                        length = 0;
                        for (int i = 0; i < numberOfLengthBytes && index < data.Length; i++)
                        {
                            length = (length << 8) | data[index++];
                        }
                    }

                    // Kontrollera om vi har hittat rätt tagg
                    if (tag == expectedTag && index + length <= data.Length)
                    {
                        byte[] value = new byte[length];
                        Array.Copy(data, index, value, 0, length);
                        return value;
                    }

                    // Hoppa över värdet om det inte var taggen vi letade efter
                    index += length;
                }

                // Logga datan för felsökning
                Console.WriteLine($"Full data: {BitConverter.ToString(data)}");
                throw new Exception($"Tag {expectedTag:X2} not found in response");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in ParseTLV: {ex.Message}");
                Console.WriteLine($"Data: {BitConverter.ToString(data)}");
                throw;
            }
        }



        private async Task<bool> PerformKeyExchange()
        {
            Console.WriteLine("-------------------------------------------------------- PerformKeyExchange started...");
            try
            {
                var curve = TeleTrusTNamedCurves.GetByName("brainpoolP384r1");
                var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

                // Generera ECDH nyckelpar
                var keyGen = GeneratorUtilities.GetKeyPairGenerator("ECDH");
                var keyGenParams = new ECKeyGenerationParameters(domain, new SecureRandom());
                keyGen.Init(keyGenParams);
                var keyPair = keyGen.GenerateKeyPair();

                this.privateKeyParameters = (ECPrivateKeyParameters)keyPair.Private;
                this.ourPublicKey = ((ECPublicKeyParameters)keyPair.Public).Q;

                // Bygg kommandot
                var keyExchangeCommand = new List<byte>
        {
            0x10,    // CLA (command chaining)
            0x86,    // INS
            0x00,    // P1
            0x00,    // P2
            0x00,    // Lc (uppdateras senare)
            0x7C,    // Dynamic Authentication Data
            0x00,    // Längd (uppdateras senare)
            0x83,    // Ephemeral Public Key tag för key agreement
            0x00     // Längd (uppdateras senare)
        };

                var encodedPoint = ourPublicKey.GetEncoded(false);
                keyExchangeCommand.AddRange(encodedPoint);

                // Uppdatera längder
                int pointLength = encodedPoint.Length;
                keyExchangeCommand[8] = (byte)pointLength;
                keyExchangeCommand[6] = (byte)(pointLength + 2);
                keyExchangeCommand[4] = (byte)(keyExchangeCommand[6] + 2);
                keyExchangeCommand.Add(0x65);

                Console.WriteLine($"Sending key exchange command: {BitConverter.ToString(keyExchangeCommand.ToArray())}");

                var response = await isoDep.TransceiveAsync(keyExchangeCommand.ToArray());
                Console.WriteLine($"Key exchange response: {BitConverter.ToString(response)}");

                if (!IsSuccessful(response))
                {
                    Console.WriteLine("Key exchange failed");
                    return false;
                }

                // Extrahera deras publika nyckel
                var chipPublicKeyBytes = ParseTLV(response, 0x84);
                this.theirPublicKey = curve.Curve.DecodePoint(chipPublicKeyBytes);

                // Beräkna shared secret point
                var rawSharedSecret = theirPublicKey.Multiply(privateKeyParameters.D).Normalize();

                // Spara bara x-koordinaten som shared secret
                var rawSharedSecretEncoded = rawSharedSecret.GetEncoded(false);
                var xCoordinate = new byte[48]; // 48 bytes för P-384
                Array.Copy(rawSharedSecretEncoded, 1, xCoordinate, 0, 48);

                // Spara x-koordinaten som shared secret
                this.sharedSecret = rawSharedSecret;

                Console.WriteLine($"X-coordinate shared secret: {BitConverter.ToString(xCoordinate)}");

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in PerformKeyExchange: {ex.Message}");
                return false;
            }
        }

        // Console.WriteLine("-------------------------------------------------------- VerifyAuthenticationToken started...");

        private async Task<bool> VerifyAuthenticationToken()
        {
            Console.WriteLine("-------------------------------------------------------- VerifyAuthenticationToken started...");
            try
            {
                // 1. Beräkna KSMAC
                byte[] ksmac;
                using (var sha256 = SHA256.Create())
                {
                    var kdfMacInput = new List<byte>();

                    // Extrahera x-koordinaten från shared secret och padda till 64 bytes
                    var sharedSecretBytes = sharedSecret.GetEncoded(false);
                    var xCoordinate = new byte[48];
                    Array.Copy(sharedSecretBytes, 1, xCoordinate, 0, 48);
                    var xCoordinatePadded = new byte[64];
                    Array.Copy(xCoordinate, 0, xCoordinatePadded, 0, xCoordinate.Length);

                    // KDF för MAC-nyckel enligt ICAO spec
                    kdfMacInput.AddRange(xCoordinatePadded);
                    kdfMacInput.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x02 });  // Counter för MAC
                    kdfMacInput.AddRange(new byte[12]);   // Padding med nollor

                    ksmac = sha256.ComputeHash(kdfMacInput.ToArray()).Take(16).ToArray(); // Ta endast 16 bytes
                }

                var mac = new CMac(new AesEngine(), 128);

                // 2. Bygg TIC input data (för terminalen)
                var ticInputData = new List<byte>();
                ticInputData.AddRange(new byte[] { 0x7F, 0x49, 0x4F });  // Header med fast längd
                byte[] protocolOID = new byte[] { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04 };
                ticInputData.AddRange(new byte[] { 0x06, 0x0A });  // OID tag och längd
                ticInputData.AddRange(protocolOID);
                ticInputData.AddRange(new byte[] { 0x86, (byte)ourPublicKey.GetEncoded(false).Length });
                ticInputData.AddRange(ourPublicKey.GetEncoded(false));

                // 3. Bygg TPCD input data (för chip)
                var tpcdInputData = new List<byte>();
                tpcdInputData.AddRange(new byte[] { 0x7F, 0x49, 0x4F });  // Header med fast längd
                tpcdInputData.AddRange(new byte[] { 0x06, 0x0A });  // OID tag och längd
                tpcdInputData.AddRange(protocolOID);
                tpcdInputData.AddRange(new byte[] { 0x86, (byte)theirPublicKey.GetEncoded(false).Length });
                tpcdInputData.AddRange(theirPublicKey.GetEncoded(false));

                // 4. Beräkna tokens
                mac.Init(new KeyParameter(ksmac));
                mac.BlockUpdate(tpcdInputData.ToArray(), 0, tpcdInputData.Count);
                byte[] tpcdToken = new byte[16];
                mac.DoFinal(tpcdToken, 0);
                tpcdToken = tpcdToken.Take(8).ToArray(); // Ta endast de första 8 bytes

                mac.Reset(); // Reset MAC innan TIC-beräkning
                mac.Init(new KeyParameter(ksmac));
                mac.BlockUpdate(ticInputData.ToArray(), 0, ticInputData.Count);
                byte[] ticToken = new byte[16];
                mac.DoFinal(ticToken, 0);
                ticToken = ticToken.Take(8).ToArray(); // Ta endast de första 8 bytes

                // 5. Bygg kommandot med TPCD token
                var authTokenCommand = new List<byte>
        {
            0x00,    // CLA
            0x86,    // INS
            0x00,    // P1
            0x00,    // P2
            (byte)(tpcdToken.Length + 4),  // Lc = 4 bytes header + token length
            0x7C,    // Dynamic Authentication Data
            (byte)(tpcdToken.Length + 2),  // Length = token length + 2
            0x85,    // Authentication Token tag
            (byte)tpcdToken.Length,  // Token length
        };
                authTokenCommand.AddRange(tpcdToken);
                authTokenCommand.Add(0x00);  // Le byte

                // Debug info
                Console.WriteLine($"KSMAC: {BitConverter.ToString(ksmac)}");
                Console.WriteLine($"TIC input: {BitConverter.ToString(ticInputData.ToArray())}");
                Console.WriteLine($"TPCD input: {BitConverter.ToString(tpcdInputData.ToArray())}");
                Console.WriteLine($"TIC token: {BitConverter.ToString(ticToken)}");
                Console.WriteLine($"TPCD token: {BitConverter.ToString(tpcdToken)}");
                Console.WriteLine($"Command: {BitConverter.ToString(authTokenCommand.ToArray())}");

                var response = await isoDep.TransceiveAsync(authTokenCommand.ToArray());
                Console.WriteLine($"Response: {BitConverter.ToString(response)}");

                if (!IsSuccessful(response))
                {
                    Console.WriteLine("Authentication failed");
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false;
            }
        }



        private byte[] DeriveKey(byte[] input)
        {
            using (var sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(input);
            }
        }

        private bool IsSuccessful(byte[] response)
        {
            if (response.Length < 2)
                return false;

            return response[response.Length - 2] == 0x90 &&
                   response[response.Length - 1] == 0x00;
        }
    }
}
