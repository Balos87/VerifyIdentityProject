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

namespace VerifyIdentityProject.Platforms.Android
{
    public class PaceProtocol
    {
        private readonly IsoDep isoDep;
        private byte[] sessionKey;
        private readonly string mrz;
        private Org.BouncyCastle.Math.EC.ECPoint mappedPoint;  // Från Map response
        private Org.BouncyCastle.Math.EC.ECPoint sharedSecret; // Från Key exchange
        private AsymmetricKeyParameter privateKey;
        private ECPrivateKeyParameters privateKeyParameters;
        private Org.BouncyCastle.Math.EC.ECPoint ourPublicKey;        // Vår publika nyckel från Key Agreement (steg 3)
        private Org.BouncyCastle.Math.EC.ECPoint theirPublicKey;      // Deras publika nyckel från Key Agreement (steg 3)

        public PaceProtocol(IsoDep isoDep, string mrz)
        {
            this.isoDep = isoDep;
            this.mrz = mrz;
        }

        public async Task<bool> PerformPaceProtocol()
        {
            isoDep.Timeout = 400000;
            try
            {
                // 1. MSE:SET AT
                if (!await SelectPaceProtocol())
                    return false;

                // 2. Få krypterad nonce
                var encryptedNonce = await GetEncryptedNonce();
                if (encryptedNonce == null)
                    return false;

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

        private async Task<bool> SelectPaceProtocol()
        {
            // Protocoll OID
            byte[] protocolOID = new byte[] { 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04 };

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
                0x10     // Parameter ID för NIST P-224
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
        private byte[] DecryptNonce(byte[] encryptedNonce)
        {
            Console.WriteLine("-------------------------------------------------------- DecryptNonce started...");

            // För AES-256 behöver vi 32 bytes nyckel
            using (var sha1 = SHA1.Create())
            {
               var key = CalculateMRZKey(mrz);

                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
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

        private byte[] CalculateMRZKey(string mrzData)
        {
            // Hash med SHA-1
            using (var sha1 = SHA1.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(mrzData);
                byte[] hash = sha1.ComputeHash(inputBytes);
                byte[] key = new byte[32];  // För AES-256
                Array.Copy(hash, key, Math.Min(hash.Length, 32));
                return key;
            }
        }


        private async Task<bool> GenerateAndSendMappedParameters(byte[] decryptedNonce)
        {
            Console.WriteLine("-------------------------------------------------------- GenerateAndSendMappedParameters started...");
            try
            {
                var curve = TeleTrusTNamedCurves.GetByName("brainpoolP384r1");
                var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

                var mapCommand = new List<byte>
                {
                    0x10,    // CLA med command chaining
                    0x86,    // INS (GENERAL AUTHENTICATE)
                    0x00,    // P1
                    0x00,    // P2
                    0x00,    // Lc (uppdateras senare)
                    0x7C,    // Dynamic Authentication Data tag
                    0x00,    // Längd (uppdateras senare)
                    0x81,    // Map Nonce tag
                    0x00     // Längd (uppdateras senare)
                };

                // Konvertera nonce till punkt
                var s = new Org.BouncyCastle.Math.BigInteger(1, decryptedNonce);
                var mappedPoint = domain.G.Multiply(s).Normalize();
                var encodedPoint = mappedPoint.GetEncoded(false);

                mapCommand.AddRange(encodedPoint);

                // Uppdatera längder för 384-bit kurva
                int pointLength = encodedPoint.Length;
                mapCommand[8] = (byte)pointLength;
                mapCommand[6] = (byte)(pointLength + 2);
                mapCommand[4] = (byte)(mapCommand[6] + 2);
                mapCommand.Add(0x65);  // Le byte (från tidigare försök där chipet indikerade 0x65)

                Console.WriteLine($"Using curve: brainpoolP384r1");
                Console.WriteLine($"Point length: {pointLength}");
                Console.WriteLine($"Total command length: {mapCommand.Count}");
                Console.WriteLine($"Mapping command: {BitConverter.ToString(mapCommand.ToArray())}");

                var response = await isoDep.TransceiveAsync(mapCommand.ToArray());
                Console.WriteLine($"Map response: {BitConverter.ToString(response)}");

                // Spara mappedPoint från svaret
                var mappedPointBytes = response.Skip(4).Take(response.Length - 6).ToArray(); // Skippa headers och status
                this.mappedPoint = curve.Curve.DecodePoint(mappedPointBytes);

                return IsSuccessful(response);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false;
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

                // Spara privata nyckeln för senare
                this.privateKeyParameters = (ECPrivateKeyParameters)keyPair.Private;
                // Spara vår publika nyckel
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

                // Hämta och lägg till publika nyckeln
                var publicPoint = ((ECPublicKeyParameters)keyPair.Public).Q;
                var encodedPoint = publicPoint.GetEncoded(false);
                keyExchangeCommand.AddRange(encodedPoint);

                // Uppdatera längder
                int pointLength = encodedPoint.Length;
                keyExchangeCommand[8] = (byte)pointLength;               // Längd för public key
                keyExchangeCommand[6] = (byte)(pointLength + 2);         // Längd för data
                keyExchangeCommand[4] = (byte)(keyExchangeCommand[6] + 2); // Total längd
                keyExchangeCommand.Add(0x65);                           // Le byte

                Console.WriteLine($"Key exchange point length: {pointLength}");
                Console.WriteLine($"Sending key exchange command: {BitConverter.ToString(keyExchangeCommand.ToArray())}");

                var response = await isoDep.TransceiveAsync(keyExchangeCommand.ToArray());
                Console.WriteLine($"Key exchange response: {BitConverter.ToString(response)}");

                // Beräkna shared secret
                var chipPublicKeyBytes = response.Skip(4).Take(response.Length - 6).ToArray();
                var chipPublicKey = curve.Curve.DecodePoint(chipPublicKeyBytes);
                this.sharedSecret = chipPublicKey.Multiply(privateKeyParameters.D).Normalize();
                // Spara deras publika nyckel
                this.theirPublicKey = curve.Curve.DecodePoint(chipPublicKeyBytes);

                // Beräkna shared secret som tidigare
                this.sharedSecret = theirPublicKey.Multiply(privateKeyParameters.D).Normalize();

                if (!IsSuccessful(response))
                {
                    Console.WriteLine("Key exchange failed");
                    return false;
                }


                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in PerformKeyExchange: {ex.Message}");
                return false;
            }
        }


        private async Task<bool> VerifyAuthenticationToken()
        {
        Console.WriteLine("-------------------------------------------------------- VerifyAuthenticationToken started...");
            try
            {
                var mac = new CMac(new AesEngine(), 128);

                // Använd shared secret för att generera MAC-nyckel
                using (var sha256 = SHA256.Create())
                {
                    var sharedSecretEncoded = sharedSecret.GetEncoded(false);
                    var macKey = sha256.ComputeHash(sharedSecretEncoded);
                    mac.Init(new KeyParameter(macKey));
                }

                // Bygg data för MAC-beräkning
                var dataForMac = new List<byte>();

                // Lägg till punkterna i ordning
                var ourKeyEncoded = ourPublicKey.GetEncoded(false);
                var theirKeyEncoded = theirPublicKey.GetEncoded(false);

                dataForMac.AddRange(ourKeyEncoded);    // Vår publika nyckel från steg 3
                dataForMac.AddRange(theirKeyEncoded);  // Deras publika nyckel från steg 3

                // Beräkna MAC
                mac.BlockUpdate(dataForMac.ToArray(), 0, dataForMac.Count);
                byte[] authToken = new byte[mac.GetMacSize()];
                mac.DoFinal(authToken, 0);

                // Bygg kommandot
                var authTokenCommand = new List<byte>
        {
            0x00,    // CLA
            0x86,    // INS
            0x00,    // P1
            0x00,    // P2
            0x00,    // Lc
            0x7C,    // Dynamic Authentication Data
            0x00,    // Length
            0x85,    // Authentication Token tag
            (byte)authToken.Length,
        };

                authTokenCommand.AddRange(authToken);

                // Uppdatera längder
                authTokenCommand[6] = (byte)(authToken.Length + 2);
                authTokenCommand[4] = (byte)(authTokenCommand[6] + 2);
                authTokenCommand.Add(0x65);

                Console.WriteLine($"Data for MAC length: {dataForMac.Count}");
                Console.WriteLine($"Our public key length: {ourKeyEncoded.Length}");
                Console.WriteLine($"Their public key length: {theirKeyEncoded.Length}");
                Console.WriteLine($"Auth token: {BitConverter.ToString(authToken)}");
                Console.WriteLine($"Full command: {BitConverter.ToString(authTokenCommand.ToArray())}");

                var response = await isoDep.TransceiveAsync(authTokenCommand.ToArray());
                Console.WriteLine($"Response: {BitConverter.ToString(response)}");

                return IsSuccessful(response);
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
