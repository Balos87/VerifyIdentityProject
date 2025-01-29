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

namespace VerifyIdentityProject.Platforms.Android
{


    public class PaceProtocol
    {
        private readonly IsoDep isoDep; // Din IsoDep-wrapper
        private byte[] sessionKey;
        private readonly string mrz; // CAN/MRZ kod
        private ECDiffieHellman ephemeralEcdh;
        // NIST P-224 generator point coordinates
        private static readonly byte[] G_X = new byte[] {
            0xB7, 0x0E, 0x0C, 0xBD, 0x6B, 0xB4, 0xBF, 0x7F,
            0x32, 0x13, 0x90, 0xB9, 0x4A, 0x03, 0xC1, 0xD3,
            0x56, 0xC2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xD6,
            0x11, 0x5C, 0x1D, 0x21
        };

        private static readonly byte[] G_Y = new byte[] {
            0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb,
            0x4c, 0x22, 0xdf, 0xe6, 0xcd, 0x43, 0x75, 0xa0,
            0x5a, 0x07, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99,
            0x85, 0x00, 0x7e, 0x34
        };
        // NIST P-224 curve parameters
        private static readonly BigInteger p224 = BigInteger.Parse("26959946667150639794667015087019630673557916260026308143510066298881");
        private static readonly BigInteger a224 = BigInteger.Parse("-3");
        private static readonly BigInteger b224 = BigInteger.Parse("18958286285566608000408668544493926415504680968679321075787234672564");

        // NIST P-224 kurvan konstanter
        private static readonly byte[] P224_P = new byte[] {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

        private static readonly byte[] P224_A = new byte[] {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE
};

        private static readonly byte[] P224_B = new byte[] {
    0xB4, 0x05, 0x0A, 0x85, 0x0C, 0x04, 0xB3, 0xAB, 0xF5, 0x41, 0x32, 0x56, 0x50, 0x44, 0xB0, 0xB7,
    0xD7, 0xBF, 0xD8, 0xBA, 0x27, 0x0B, 0x39, 0x43, 0x23, 0x55, 0xFF, 0xB4
};

        private static readonly byte[] P224_Order = new byte[] {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x16, 0xA2,
    0xE0, 0xB8, 0xF0, 0x3E, 0x13, 0xDD, 0x29, 0x45, 0x5C, 0x5C, 0x2A, 0x3D
};

        private static readonly byte[] P224_Gx = new byte[] {
    0xB7, 0x0E, 0x0C, 0xBD, 0x6B, 0xB4, 0xBF, 0x7F, 0x32, 0x13, 0x90, 0xB9, 0x4A, 0x03, 0xC1, 0xD3,
    0x56, 0xC2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xD6, 0x11, 0x5C, 0x1D, 0x21
};

        private static readonly byte[] P224_Gy = new byte[] {
    0xBD, 0x37, 0x63, 0x88, 0xB5, 0xF7, 0x23, 0xFB, 0x4C, 0x22, 0xDF, 0xE6, 0xCD, 0x43, 0x75, 0xA0,
    0x5A, 0x07, 0x47, 0x64, 0x44, 0xD5, 0x81, 0x99, 0x85, 0x00, 0x7E, 0x34
};


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
                Console.WriteLine("GetEncryptedNonce started...");
                var encryptedNonce = await GetEncryptedNonce();
                if (encryptedNonce == null)
                    return false;

                // 3. Dekryptera nonce
                Console.WriteLine("DecryptNonce started...");
                var decryptedNonce = DecryptNonce(encryptedNonce);

                // 4. Generera och skicka mappade parametrar
                Console.WriteLine("GenerateAndSendMappedParameters started...");
                var mappedParams = await GenerateAndSendMappedParameters(decryptedNonce);
                if (!mappedParams)
                    return false;

                // 5. Utför ECDH nyckelutbyte
                Console.WriteLine("PerformKeyExchange started...");
                if (!await PerformKeyExchange())
                    return false;

                // 6. Verifiera autentiseringstoken
                Console.WriteLine("VerifyAuthenticationToken started...");
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
            // Generera 16-byte AES nyckel från CAN/MRZ
            byte[] key = new byte[16];
            using (var sha1 = SHA1.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(mrz);
                byte[] hash = sha1.ComputeHash(inputBytes);

                // Använd de första 16 bytes som AES-nyckel
                byte[] key2 = new byte[16];
                Array.Copy(hash, key, 16);

                key = key2;
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;  // Ändrat till NoPadding
                aes.IV = new byte[16]; // Nollställd IV

                using (var decryptor = aes.CreateDecryptor())
                {
                    var decyptedNonce = decryptor.TransformFinalBlock(encryptedNonce, 0, encryptedNonce.Length);
                    Console.WriteLine($"DecryptNonce: {BitConverter.ToString(decyptedNonce)}");
                    return decyptedNonce;
                }
            }
        }

        private async Task<bool> GenerateAndSendMappedParameters(byte[] decryptedNonce)
        {
            Console.WriteLine("GenerateAndSendMappedParameters started...");
            try
            {
                var curve = NistNamedCurves.GetByName("P-224");
                var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

                // Generera nyckelpar för mapping
                var keyGen = GeneratorUtilities.GetKeyPairGenerator("ECDH");
                var keyGenParams = new ECKeyGenerationParameters(domain, new SecureRandom());
                keyGen.Init(keyGenParams);
                var keyPair = keyGen.GenerateKeyPair();

                // Bygg Map Nonce kommando (Steg 2)
                var mappingCommand = new List<byte>
        {
            0x10,    // CLA med command chaining
            0x86,    // INS (GENERAL AUTHENTICATE)
            0x00,    // P1
            0x00,    // P2
            0x00,    // Lc (uppdateras senare)
            0x7C,    // Dynamic Authentication Data tag
            0x00,    // Längd (uppdateras senare)
            0x81,    // Mapping Data tag (enligt spec)
            0x39     // Längd för punkten
        };

                var publicPoint = ((ECPublicKeyParameters)keyPair.Public).Q;
                var encodedPoint = publicPoint.GetEncoded(false);

                // Lägg till punkten
                mappingCommand.AddRange(encodedPoint);

                // Uppdatera längder
                var innerLength = encodedPoint.Length;
                mappingCommand[6] = (byte)(innerLength + 2);  // +2 för tag och längd
                mappingCommand[4] = (byte)(mappingCommand[6] + 2);  // +2 för outer tag och längd

                Console.WriteLine($"Encoded point length: {encodedPoint.Length}");
                Console.WriteLine($"Total command length: {mappingCommand.Count}");
                Console.WriteLine($"Sending mapping command: {BitConverter.ToString(mappingCommand.ToArray())}");

                var response = await isoDep.TransceiveAsync(mappingCommand.ToArray());
                Console.WriteLine($"Mapping response: {BitConverter.ToString(response)}");

                return IsSuccessful(response);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in GenerateAndSendMappedParameters: {ex.Message}");
                return false;
            }
        }

        private List<byte> MapPoint(BigInteger s, byte[] _, byte[] __, ECParameters curveParams)
        {
            const int P224_COORD_LENGTH = 28;  // Exakt längd för P-224 koordinater

            // Säkerställ att s är positiv och inom kurvans ordning
            s = s % p224;
            if (s < 0) s += p224;

            // Utför punktmultiplikation med trimmat s
            (BigInteger resultX, BigInteger resultY) = ScalarMultiply(
                new BigInteger(G_X),
                new BigInteger(G_Y),
                s,
                p224,
                a224);

            // Formatera punkten exakt som chipet förväntar sig
            List<byte> mappedPoint = new List<byte>();
            mappedPoint.Add(0x04);  // Uncompressed point identifier

            // Säkerställ exakt 28 bytes per koordinat
            byte[] xBytes = resultX.ToByteArray().Reverse().ToArray();
            byte[] yBytes = resultY.ToByteArray().Reverse().ToArray();

            // Padda till exakt längd om det behövs
            if (xBytes.Length < P224_COORD_LENGTH)
            {
                xBytes = new byte[P224_COORD_LENGTH - xBytes.Length]
                    .Concat(xBytes)
                    .ToArray();
            }
            else if (xBytes.Length > P224_COORD_LENGTH)
            {
                xBytes = xBytes.Skip(xBytes.Length - P224_COORD_LENGTH).ToArray();
            }

            if (yBytes.Length < P224_COORD_LENGTH)
            {
                yBytes = new byte[P224_COORD_LENGTH - yBytes.Length]
                    .Concat(yBytes)
                    .ToArray();
            }
            else if (yBytes.Length > P224_COORD_LENGTH)
            {
                yBytes = yBytes.Skip(yBytes.Length - P224_COORD_LENGTH).ToArray();
            }

            mappedPoint.AddRange(xBytes);
            mappedPoint.AddRange(yBytes);

            return mappedPoint;
        }

        private (BigInteger x, BigInteger y) ScalarMultiply(BigInteger x, BigInteger y, BigInteger scalar, BigInteger p, BigInteger a)
        {
            BigInteger resultX = 0;
            BigInteger resultY = 0;
            bool isFirst = true;

            // Ersatt TestBit med egen bit-check
            for (int i = scalar.ToString("X").Length * 4 - 1; i >= 0; i--)
            {
                if (!isFirst)
                {
                    (resultX, resultY) = PointDouble(resultX, resultY, p, a);
                }

                // Kontrollera bit utan TestBit
                if ((scalar & (BigInteger.One << i)) != 0)
                {
                    if (isFirst)
                    {
                        resultX = x;
                        resultY = y;
                        isFirst = false;
                    }
                    else
                    {
                        (resultX, resultY) = PointAdd(resultX, resultY, x, y, p);
                    }
                }
            }

            return (resultX, resultY);
        }

        private (BigInteger x, BigInteger y) PointDouble(BigInteger x, BigInteger y, BigInteger p, BigInteger a)
        {
            if (y == 0)
                return (0, 0);

            // s = (3x² + a) / (2y)
            BigInteger s = ((3 * x * x + a) * ModInverse(2 * y, p)) % p;

            // x' = s² - 2x
            BigInteger xr = (s * s - 2 * x) % p;
            if (xr < 0) xr += p;

            // y' = s(x - x') - y
            BigInteger yr = (s * (x - xr) - y) % p;
            if (yr < 0) yr += p;

            return (xr, yr);
        }

        private (BigInteger x, BigInteger y) PointAdd(BigInteger x1, BigInteger y1, BigInteger x2, BigInteger y2, BigInteger p)
        {
            if (x1 == 0 && y1 == 0) return (x2, y2);
            if (x2 == 0 && y2 == 0) return (x1, y1);
            if (x1 == x2 && y1 == -y2) return (0, 0);

            BigInteger s;
            if (x1 == x2 && y1 == y2)
                return PointDouble(x1, y1, p, -3);  // a = -3 för NIST P-256

            // s = (y2 - y1) / (x2 - x1)
            s = ((y2 - y1) * ModInverse((x2 - x1) % p, p)) % p;

            // x3 = s² - x1 - x2
            BigInteger x3 = (s * s - x1 - x2) % p;
            if (x3 < 0) x3 += p;

            // y3 = s(x1 - x3) - y1
            BigInteger y3 = (s * (x1 - x3) - y1) % p;
            if (y3 < 0) y3 += p;

            return (x3, y3);
        }

        private BigInteger ModInverse(BigInteger value, BigInteger modulus)
        {
            if (value < 0)
                value = value % modulus;

            BigInteger a = value;
            BigInteger b = modulus;
            BigInteger x = 1;
            BigInteger y = 0;
            BigInteger x1 = 0;
            BigInteger y1 = 1;
            BigInteger q;
            BigInteger temp;

            while (b != 0)
            {
                q = a / b;
                temp = a % b;
                a = b;
                b = temp;

                temp = x - q * x1;
                x = x1;
                x1 = temp;

                temp = y - q * y1;
                y = y1;
                y1 = temp;
            }

            if (x < 0)
                x += modulus;

            return x;
        }

        private async Task<bool> PerformKeyExchange()
        {
            // Generera ny ECDH nyckel för nyckelutbytet
            using (ECDiffieHellman ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
            {
                var publicKey = ecdh.PublicKey.ExportSubjectPublicKeyInfo();

                var keyExchangeCommand = new List<byte>
            {
                0x10,    // CLA (command chaining)
                0x86,    // INS
                0x00,    // P1
                0x00,    // P2
                0x00,    // Lc (uppdateras senare)
                0x7C,    // Dynamic Authentication Data
                0x00     // Längd (uppdateras senare)
            };

                keyExchangeCommand.AddRange(publicKey);

                // Uppdatera längder
                keyExchangeCommand[6] = (byte)(publicKey.Length);
                keyExchangeCommand[4] = (byte)(publicKey.Length + 2);

                var response = await isoDep.TransceiveAsync(keyExchangeCommand.ToArray());
                if (!IsSuccessful(response))
                    return false;

                // Beräkna gemensam hemlighet här
                // Chipets publika nyckel finns i response
                return true;
            }
        }

        private async Task<bool> VerifyAuthenticationToken()
        {
            // Generera och skicka autentiseringstoken
            var authTokenCommand = new List<byte>
        {
            0x00,    // CLA (sista kommandot, ingen chaining)
            0x86,    // INS
            0x00,    // P1
            0x00,    // P2
            0x00,    // Lc (uppdateras senare)
            0x7C,    // Dynamic Authentication Data
            0x00     // Längd (uppdateras senare)
        };

            // Beräkna och lägg till autentiseringstoken här
            // ...

            var response = await isoDep.TransceiveAsync(authTokenCommand.ToArray());
            return IsSuccessful(response);
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
