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
        private AsymmetricKeyParameter privateKey;
        private ECPrivateKeyParameters privateKeyParameters;
        private byte[] KSMAC;
        private byte[] KSEnc;


        public PaceProtocol(IsoDep isoDep, string mrz, byte[]oid)
        {
            this.isoDep = isoDep;
            this.mrz = mrz;
            this.oid = oid;
        }

        public bool PerformPaceProtocol()
        {
            Console.WriteLine("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");
            Console.WriteLine("PerformPaceProtocol");

            isoDep.Timeout = 400000;
            try
            {
                // 1. MSE:Set AT command to initiate PACE
                if (!MseSetAtSelectPaceProtocol())
                    return false;

                // 2. Get encrypted nonce from the passport
                var encryptedNonce = GetEncryptedNonce();
                if (encryptedNonce == null)
                    return false;

                // 3. Decrypt the nonce using the password derived from the MRZ
                var decryptedNonce = DecryptNonce(encryptedNonce);

                // 4. Generate and exchange ephemeral keys
                var mappedParams = GenerateAndSendMappedParameters(decryptedNonce);
                if (!mappedParams)
                    return false;

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"PACE-protokoll misslyckades: {ex.Message}");
                
                return false;
            }
        }
       
        private bool MseSetAtSelectPaceProtocol()
        {
            byte[] protocolOID = oid;

            // Build MSE:SET AT command
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

            // Adding OID 
            command.AddRange(protocolOID);

            // Password reference (0x83 tag)
            command.AddRange(new byte[]
            {
                0x83,    // Tag for password reference
                0x01,    // Length of value
                0x01     // Value: 0x01 for MRZ
            });

            // Adding domain parameters reference (0x84 tag)
            command.AddRange(new byte[]
            {
                0x84,    // Tag for domain parameters
                0x01,    // Length of value
                0x10     // Parameter ID 
            });

            // Uppdating Lc (total length of data)
            command[4] = (byte)(command.Count - 5);

            byte[] finalCommand = command.ToArray();
            // Console.WriteLine($"mseSetAtCommand: {BitConverter.ToString(finalCommand)}");

            var response = isoDep.Transceive(finalCommand);
            // Console.WriteLine($"response: {BitConverter.ToString(response)}");

            return IsSuccessful(response);
        }

        private byte[] GetEncryptedNonce()
        {
            // Console.WriteLine("-------------------------------------------------------- GetEncryptedNonce started...");
            var getNonceCommand = new byte[]
            {
                0x10,    // CLA (command chaining)
                0x86,    // INS
                0x00,    // P1
                0x00,    // P2
                0x02,    // Lc
                0x7C,    // Dynamic Authentication Data
                0x00,    // Empty data
                0x00     // Le (expected response, set to 0x00 to get length indication)
            };
            // Console.WriteLine($"Sending getNonceCommand: {BitConverter.ToString(getNonceCommand)}");

            var response = isoDep.Transceive(getNonceCommand);
            // Console.WriteLine($"GetEncryptedNonce response: {BitConverter.ToString(response)}");

            if (!IsSuccessful(response))
                return null;

            // return the encrypted nonce extracted from the response
            return ParseEncryptedNonce(response);
        }

        private byte[] ParseEncryptedNonce(byte[] response)
        {
            //  Console.WriteLine("-------------------------------------------------------- ParseEncryptedNonce started...");
            try
            {
                // Remove status bytes (90 00)
                var data = response.Take(response.Length - 2).ToArray();

                if (data[0] != 0x7C)
                    throw new Exception("Invalid outer tag in nonce response");

                // Skip outer tag and length
                int index = 2;

                if (data[index] != 0x80)
                    throw new Exception("Couldnt find nonce tag (80)");

                // Get nonce length
                int nonceLength = data[index + 1];

                // Extract the nonce data
                byte[] nonce = new byte[nonceLength];
                Array.Copy(data, index + 2, nonce, 0, nonceLength);

                //  Console.WriteLine($"Extracted nonce length: {nonceLength}");
                //  Console.WriteLine($"Extracted nonce: {BitConverter.ToString(nonce)}");

                return nonce;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error when parsing nonce: {ex.Message}");
                return null;
            }
        }

        private byte[] DecryptNonce(byte[] encryptedNonce)
        {
            // Console.WriteLine("-------------------------------------------------------- DecryptNonce started...");

            using (var sha1 = SHA1.Create())
            {
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
                        //  Console.WriteLine($"DecryptNonce: {BitConverter.ToString(decryptedNonce)}");
                        return decryptedNonce;
                    }
                }
            }
        }

        private byte[] CalculateKPiFromMrz(string mrzData)
        {
            //   Console.WriteLine("-------------------------------------------------------- Calculate KPi From Mrz started...");

            //Calculate K from MRZ
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(mrzData);
                byte[] k = sha1.ComputeHash(inputBytes);
               // Console.WriteLine($"Output k as hex: {BitConverter.ToString(k)}");

                // Calculate KPi from K
                var KPi = CalculateKPi(k);
                //  Console.WriteLine("-------------------------------------------------------- Calculate KPi From Mrz finished...");
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

            //  Console.WriteLine($"Counter bytes: {BitConverter.ToString(counter)}");

            // Concatenate K with counter
            byte[] combined = new byte[k.Length + counter.Length];
            k.CopyTo(combined, 0);
            counter.CopyTo(combined, k.Length);

            //  Console.WriteLine($"Combined input for KDF: {BitConverter.ToString(combined)}");

            // Calculate SHA-256 hash
            using (var sha256 = SHA256.Create())
            {
                byte[] fullHash = sha256.ComputeHash(combined);
                //    Console.WriteLine($"Full SHA-256 hash output: {BitConverter.ToString(fullHash)}");

                // 256-bit AES key = Take first 32 bytes.
                byte[] kPi = new byte[32];
                Array.Copy(fullHash, kPi, 32);

                //    Console.WriteLine($"Final Kπ (32 bytes): {BitConverter.ToString(kPi)}");
                return kPi;
            }
        }

        private bool GenerateAndSendMappedParameters(byte[] decryptedNonce)
        {
            //  Console.WriteLine("-------------------------------------------------------- GenerateAndSendMappedParameters started...");
            try
            {
                var curve = TeleTrusTNamedCurves.GetByName("brainpoolP384r1");
                var curveParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

                var keyGenerator = new ECDHKeyGenerator(curveParams);

                // Genererate KeyPair
                var keyPair = keyGenerator.GenerateKeyPair();

                // Converting public key to byte array (prepare for sending to chip)
                byte[] publicKeyBytes = ECDHKeyGenerator.PublicKeyToBytes(keyPair.PublicKey);
                //  Console.WriteLine($"publicKeyBytes: {BitConverter.ToString(publicKeyBytes)}");

                // Create APDU for sending public key
                var ourPublicKeyApdu = ECDHKeyGenerator.BuildMapNonceCommand(publicKeyBytes);
                //  Console.WriteLine($"Sending ourPublicKey: {BitConverter.ToString(ourPublicKeyApdu)}");

                // Sending our public key and recieving chip public key
                var chipPublicKey = isoDep.Transceive(ourPublicKeyApdu);
                // Console.WriteLine($"Recieved chipPublicKey: {BitConverter.ToString(chipPublicKey)}");

                // Extract chip public key from response
                var exractedChipPublicKey = ECDHKeyGenerator.ExtractPublicKeyFromResponse(chipPublicKey);
                //  Console.WriteLine($"exractedChipPublicKey: {BitConverter.ToString(exractedChipPublicKey)}");

                // Calculates H with help our private key, chip public key and curveParams.
                var H = ECDHKeyGenerator.CalculateH(curveParams, keyPair.PrivateKey, exractedChipPublicKey);
                //  Console.WriteLine($"Calculated H: {BitConverter.ToString(H.GetEncoded(false))}");
                if (!H.IsValid())
                    throw new Exception("Error: H is not a valid point on the curve!");

                // Create BigInteger from decryptedNonce
                var bigIntegerS = ECDHKeyGenerator.SToBigInteger(decryptedNonce, curveParams);
                //  Console.WriteLine($"bigInteger(s): {bigIntegerS.ToString(16)}");

                // Create gTilde with curvparams.G and s and H
                var gTilde = curveParams.G.Multiply(bigIntegerS).Add(H).Normalize();

                if (!gTilde.IsValid())
                    throw new Exception("Fel: gTilde is not a valid point on the curve!");

                //Create keypair from our gTilde
                var gTildeKeys = keyGenerator.GenerateKeyPairWithGTilde(gTilde);
                //  Console.WriteLine($"gTildeKeys.PrivatKEy: {gTildeKeys.PrivateKey}");


                // convert our gTilde-public key to byte array
                byte[] gTildePublicKeyBytes = ECDHKeyGenerator.PublicKeyToBytes(gTildeKeys.PublicKey);
                //  Console.WriteLine($"gTildePublicKeyBytes: {gTildePublicKeyBytes}");


                // Create APDU for sending gTilde-public key
                var gTildePublicKeyAPdu = ECDHKeyGenerator.BuildKeyAgreementCommandGTilde(gTildePublicKeyBytes);
                //  Console.WriteLine($"Sending gTildePublicKeyAPdu: {BitConverter.ToString(gTildePublicKeyAPdu)}");

                // sending our gTilde-public key and recieving chip-gTilde-public key
                var chipGTildePublicKey = isoDep.Transceive(gTildePublicKeyAPdu);
                //  Console.WriteLine($"Recieved chipGTildePublicKey: {BitConverter.ToString(chipGTildePublicKey)}");

                // Extract chip-gTilde-public key from response
                var extractedChipGTildePublicKey = ECDHKeyGenerator.ExtractGTildePublicKeyFromResponse(chipGTildePublicKey);
                //  Console.WriteLine($"extractedChipGTildePublicKey: {BitConverter.ToString(extractedChipGTildePublicKey)}");

                // convert Extract chip-gTilde-public to ECPoint
                Org.BouncyCastle.Math.EC.ECPoint chipGTildePublicKeyDecoded = curveParams.Curve.DecodePoint(extractedChipGTildePublicKey);
                //  Console.WriteLine($"chipGTildePublicKeyDecoded: X:{chipGTildePublicKeyDecoded.XCoord} Y:{chipGTildePublicKeyDecoded.YCoord}");


                // Comparing our gTilde-public key with chip-gTilde-public key. They should not be the same
                if (gTildeKeys.PublicKey.Equals(chipGTildePublicKeyDecoded))
                    throw new Exception("Public keys are identical - security violation!");


                // Multiply chip-gTilde-public key with our private key to get K
                Org.BouncyCastle.Math.EC.ECPoint K = chipGTildePublicKeyDecoded.Multiply(gTildeKeys.PrivateKey).Normalize();
                if (!K.IsValid())
                    throw new Exception("Error: K is not a valid point on the curve");
                //  Console.WriteLine($"Calculated K: {BitConverter.ToString(K.GetEncoded(false))}");


                // We use K to create KSMac and KSEnc
                KSEnc = ECDHKeyGenerator.DeriveKeyFromK(K, 1);  // EncryptionKey
                KSMAC = ECDHKeyGenerator.DeriveKeyFromK(K, 2);  // AutehnticationKey

                //  Console.WriteLine($"KSEnc: {BitConverter.ToString(KSEnc)}");
                //  Console.WriteLine($"KSMAC: {BitConverter.ToString(KSMAC)}");

                //Creating a MSE:SET AT command including our public key and OID
                var inputDataForTPCD = ECDHKeyGenerator.BuildAuthenticationTokenInput(extractedChipGTildePublicKey, oid);
                var inputDataForTIC = ECDHKeyGenerator.BuildAuthenticationTokenInput(gTildePublicKeyBytes, oid);
                //  Console.WriteLine($"inputDataForTPCD: {BitConverter.ToString(inputDataForTPCD)}");
                //  Console.WriteLine($"inputDataForTIC: {BitConverter.ToString(inputDataForTIC)}");

                // Calculating aut-token TPCD och TIC. By using KSMAC and "inputData" from the last step
                var TPCD = ECDHKeyGenerator.CalculateAuthenticationToken(KSMAC, inputDataForTPCD);
                var TIC = ECDHKeyGenerator.CalculateAuthenticationToken(KSMAC, inputDataForTIC);
                // Console.WriteLine($"TPCD: {BitConverter.ToString(TPCD)}");
                // Console.WriteLine($"TIC: {BitConverter.ToString(TIC)}");

                //Building command for sending TPCD token to chip.
                var comand = ECDHKeyGenerator.BuildTokenCommand(TPCD);
                // Console.WriteLine($"sending TPCD command: {BitConverter.ToString(comand)}");

                var responseTic = isoDep.Transceive(comand);
                // Console.WriteLine($"Chip response (TIC): {BitConverter.ToString(responseTic)}");


                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false;
            }
        }

        public (byte[] KSEnc, byte[] KSMac ) GetKsEncAndKsMac()
        {
            return(KSEnc, KSMAC);
        }

        private static byte[] ParseTLV(byte[] data, byte expectedTag)
        {
            try
            {
                int index = 0;
                while (index < data.Length - 1)
                {
                    // Checkin for structured tags (7C, etc.)
                    byte tag = data[index++];
                    if (tag == 0x7C)
                    {
                        int structLength = data[index++];
                        byte[] innerData = new byte[structLength];
                        Array.Copy(data, index, innerData, 0, structLength);
                        return ParseTLV(innerData, expectedTag);
                    }

                    // Handles length 
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

                    // Check if we found the expected tag
                    if (tag == expectedTag && index + length <= data.Length)
                    {
                        byte[] value = new byte[length];
                        Array.Copy(data, index, value, 0, length);
                        return value;
                    }

                    // the value if it wasn't the tag we were looking for
                    index += length;
                }

                // Console.WriteLine($"Full data: {BitConverter.ToString(data)}");
                throw new Exception($"Tag {expectedTag:X2} not found in response");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in ParseTLV: {ex.Message}");
                //  Console.WriteLine($"Data: {BitConverter.ToString(data)}");
                throw;
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
