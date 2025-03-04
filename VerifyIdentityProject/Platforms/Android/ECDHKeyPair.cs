using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Digests;
using Xamarin.Google.ErrorProne.Annotations;
using Org.BouncyCastle.Utilities;

public class ECDHKeyPair
{
    public BigInteger PrivateKey { get; set; }
    public ECPoint PublicKey { get; set; }
}

public class ECDHKeyGenerator
{
    public readonly ECDomainParameters domainParameters;
    public readonly SecureRandom secureRandom;

    public ECDHKeyGenerator(ECDomainParameters domainParameters)
    {
        this.domainParameters = domainParameters;
        this.secureRandom = new SecureRandom();
    }

    // Hjälpmetod för att sätta upp domänparametrarna för brainpoolP384r1
    public static ECDomainParameters SetupBrainpoolP384r1()
    {
        // Hämta standardkurvparametrar för brainpoolP384r1
        X9ECParameters ecP = TeleTrusTNamedCurves.GetByName("brainpoolP384r1");

        // Skapa domänparametrar från kurvparametrarna
        return new ECDomainParameters(
            ecP.Curve,          // Kurvan
            ecP.G,              // Generator punkt G
            ecP.N,              // Ordning n
            ecP.H,              // Cofactor
            ecP.GetSeed()       // Kurvseed (kan vara null)
        );
    }

    public ECDHKeyPair GenerateKeyPair()
    {
        // 1. Generera privat nyckel med BouncyCastles inbyggda metod
        BigInteger privateKey = BigIntegers.CreateRandomInRange(
            BigInteger.One,  // Lägsta tillåtna värde
            domainParameters.N.Subtract(BigInteger.One),  // Högsta tillåtna värde (n-1)
            secureRandom  // Vår säkra slumptalsgenerator
        );

        // 2. Skapar publik nyckel. (privat nyckel * G)
        ECPoint publicKey = domainParameters.G.Multiply(privateKey).Normalize();

        if (!ValidatePublicKey(publicKey, domainParameters))
            Console.WriteLine("public key not valid!");

        return new ECDHKeyPair
        {
            PrivateKey = privateKey,
            PublicKey = publicKey
        };
    }
    private bool ValidatePublicKey(ECPoint publicKey, ECDomainParameters domainParams)
    {
        // Kontrollera att punkten ligger på kurvan
        if (!publicKey.IsValid())
        {
            return false;
        }

        // Kontrollera att punkten har rätt ordning
        if (!publicKey.Multiply(domainParams.N).IsInfinity)
        {
            return false;
        }

        // Kontrollera att punkten inte är punkten vid oändligheten
        if (publicKey.IsInfinity)
        {
            return false;
        }

        return true;
    }


    //gör en byte array av publik nyckel
    public static byte[] PublicKeyToBytes(ECPoint publicKey)
    {
        // Konvertera till okomprimerat format (0x04 || x || y)
        return publicKey.GetEncoded(false);
    }

    //metod för att bygga APDU som sedan skickar våran publika nyckel till chip
    public static byte[] BuildMapNonceCommand(byte[] publicKey)
    {
        // Längder
        byte mappingDataLength = (byte)publicKey.Length;  // len2
        byte dynamicAuthDataLength = (byte)(2 + mappingDataLength); // len1: 81 + len + data
        byte totalLength = (byte)(2 + dynamicAuthDataLength); // Lc: 7C + len + inner data

        // Skapa kommandot
        List<byte> command = new List<byte>();

        // Header
        command.Add(0x10);     // CLA (Command chaining)
        command.Add(0x86);     // INS (General Authenticate)
        command.Add(0x00);     // P1
        command.Add(0x00);     // P2
        command.Add(totalLength); // Lc

        // Dynamic Authentication Data
        command.Add(0x7C);     // Tag för Dynamic Authentication Data
        command.Add(dynamicAuthDataLength);

        // Mapping Data
        command.Add(0x81);     // Tag för Mapping Data
        command.Add(mappingDataLength);

        // Lägg till publika nyckeln (som redan innehåller 04 || x || y)
        command.AddRange(publicKey);

        // Le
        command.Add(0x00);

        return command.ToArray();
    }

    // Hjälpmetod för att validera kommandot ----------------Kanske ta bort denna?
    public static bool ValidateCommand(byte[] command)
    {
        if (command == null || command.Length < 7) return false;

        // Kontrollera header
        if (command[0] != 0x10 || command[1] != 0x86 ||
            command[2] != 0x00 || command[3] != 0x00)
            return false;

        // Kontrollera längder
        byte declaredLength = command[4];
        if (command.Length != declaredLength + 6) // 5 header bytes + Le byte
            return false;

        // Kontrollera tags
        if (command[5] != 0x7C || command[7] != 0x81)
            return false;

        return true;
    }

    public static byte[] ExtractPublicKeyFromResponse(byte[] response)
    {
        // Validera minimum längd och status bytes
        if (response == null || response.Length < 7)
            throw new Exception("response is null or to short!");

        if (response[response.Length - 2] != 0x90 || response[response.Length - 1] != 0x00)
            throw new Exception("response is not 90-00!");

        int index = 0;

        if (response[index++] != 0x7C)
            throw new Exception("response is missing 7C start-tag!");
        index++;

        if (response[index++] != 0x82)
            throw new Exception("response is missing 82 tag!");
        //here we se dataLength to the length value that is inclued in the response(61 = 97) and thats the length of the data that is following
        int dataLength = response[index++];

        if (response[index] != 0x04)
            throw new Exception("response is not uncompressed Point!");

        byte[] publicKey = new byte[dataLength];
        Array.Copy(response, index, publicKey, 0, dataLength);

        return publicKey;
    }

    public static BigInteger SToBigInteger(byte[] decryptedNonce, ECDomainParameters curveParams)
    {
        try
        {
            // Skapa BigInteger från decryptedNonce
            var s = new Org.BouncyCastle.Math.BigInteger(1, decryptedNonce);
            s = s.Mod(curveParams.N);

            // Logga `s` och `domain.N`
            Console.WriteLine($"Nonce (s): {s.ToString(16)}");
            Console.WriteLine($"Curve order (N): {curveParams.N.ToString(16)}");

            // Validera att `s` är inom giltigt intervall: 1 ≤ s ≤ n-1
            if (s.SignValue <= 0 || s.CompareTo(curveParams.N.Subtract(Org.BouncyCastle.Math.BigInteger.One)) >= 0)
                throw new Exception("Nonce value is out of range for the curve domain.");

            return (s);
        }
        catch (Exception e)
        {
            throw new Exception("Could not convert S to BigInteger", e);
        }
    }

    //1.brainpoolP384r1 parametrar  2.Vår privata nyckel från förr 3.Chippets publika nyckel som vi just extraherade
    public static ECPoint CalculateH(ECDomainParameters curveParameters, BigInteger ourPrivateKey, byte[] chipPublicKeyBytes)
    {
        // Konvertera chippets publika nyckel från bytes till ECPoint
        ECPoint chipPublicKey = curveParameters.Curve.DecodePoint(chipPublicKeyBytes);
        // Validera chippets publika nyckel
        if (!chipPublicKey.IsValid())
            throw new ArgumentException("Ogiltig publik nyckel från chip");
        // Beräkna H genom att multiplicera chippets publika nyckel med vår privata nyckel
        ECPoint H = chipPublicKey.Multiply(ourPrivateKey);
        // Validera resultatet
        if (H.IsInfinity)
            throw new InvalidOperationException("Beräkningen resulterade i ogiltig punkt");
        return H;
    }

    public ECDHKeyPair GenerateKeyPairWithGTilde(ECPoint gTilde)
    {
        // 1. Generera privat nyckel (ett slumpmässigt tal mellan 1 och n-1)
        BigInteger n = domainParameters.N; // Kurvans ordning
        BigInteger privateKey;
        do
        {
            privateKey = new BigInteger(n.BitLength, secureRandom);
        }
        while (privateKey.CompareTo(BigInteger.One) < 0 || privateKey.CompareTo(n) >= 0);

        // 2. Skapar publik nyckel. (privat nyckel * G)
        ECPoint publicKey = gTilde.Multiply(privateKey);

        return new ECDHKeyPair
        {
            PrivateKey = privateKey,
            PublicKey = publicKey
        };
    }

    public static byte[] BuildKeyAgreementCommandGTilde(byte[] publicKey)
    {
        // Längder
        byte mappingDataLength = (byte)publicKey.Length;
        byte dynamicAuthDataLength = (byte)(2 + mappingDataLength); // 83 + len + data
        byte totalLength = (byte)(2 + dynamicAuthDataLength); // 7C + len + inner data

        List<byte> command = new List<byte>();

        // Header
        command.Add(0x10);     // CLA (Command chaining)
        command.Add(0x86);     // INS (General Authenticate)
        command.Add(0x00);     // P1
        command.Add(0x00);     // P2
        command.Add(totalLength); // Lc

        // Dynamic Authentication Data
        command.Add(0x7C);
        command.Add(dynamicAuthDataLength);

        // Key Agreement Data
        command.Add(0x83);     // Tag för Key Agreement (notera: 0x83 istället för 0x81)
        command.Add(mappingDataLength);

        // Publik nyckel (innehåller redan 04 prefix)
        command.AddRange(publicKey);

        // Le
        command.Add(0x00);

        return command.ToArray();
    }

    public static byte[] ExtractGTildePublicKeyFromResponse(byte[] response)
    {
        // Validera minimum längd och status bytes
        if (response == null || response.Length < 7)
            throw new Exception("response is null or to short!");
        if (response[response.Length - 2] != 0x90 || response[response.Length - 1] != 0x00)
            throw new Exception("response is not 90-00!");

        int index = 0;

        // Kolla 7C tag
        if (response[index++] != 0x7C)
            throw new Exception("response is missing 7C start-tag!");
        index++;

        // Kolla 84 tag (ändrat från 82)
        if (response[index++] != 0x84)
            throw new Exception("response is missing 84 tag!");

        int dataLength = response[index++];

        if (response[index] != 0x04)
            throw new Exception("response is not uncompressed Point!");

        byte[] publicKey = new byte[dataLength];
        Array.Copy(response, index, publicKey, 0, dataLength);
        return publicKey;
    }

    public static byte[] DeriveKeyFromK(ECPoint K, int counter)
    {
        // Vi behöver bara x-koordinaten från K
        var normalizedK = K.Normalize();
        byte[] kBytes = normalizedK.AffineXCoord.GetEncoded();
        Console.WriteLine($"x kBytes: {BitConverter.ToString(kBytes)}");
        Console.WriteLine($"x kBytes.Length: {kBytes.Length}");

        // Skapa counter som 32-bit big-endian
        byte[] counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);

        // Concatenera K || counter
        byte[] concatenated = new byte[kBytes.Length + 4];
        kBytes.CopyTo(concatenated, 0);
        counterBytes.CopyTo(concatenated, kBytes.Length);

        // Beräkna SHA-256
        var sha256 = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
        byte[] hash = new byte[sha256.GetDigestSize()];
        sha256.BlockUpdate(concatenated, 0, concatenated.Length);
        sha256.DoFinal(hash, 0);

        return hash;  // Detta ger oss en 32-byte (256-bit) nyckel
    }


    public static byte[] BuildAuthenticationTokenInput(byte[] publicKey, byte[] oid)
    {
        List<byte> data = new List<byte>();

        // Beräkna total längd (OID längd + publik nyckel längd + extra bytes för taggar och längder)
        int totalLength = 2 + oid.Length + 2 + publicKey.Length;  // 2 bytes för varje tagg+längd combo

        // Public Key Data tag (7F49)
        data.Add(0x7F);
        data.Add(0x49);
        data.Add((byte)totalLength);  // Dynamisk längd

        // OID
        data.Add(0x06);
        data.Add((byte)oid.Length);
        data.AddRange(oid);

        // Public key
        data.Add(0x86);
        data.Add((byte)publicKey.Length);
        data.AddRange(publicKey);

        return data.ToArray();
    }

    public static byte[] CalculateAuthenticationToken(byte[] ksmac, byte[] data)
    {
        var cipher = new AesEngine();
        var mac = new CMac(cipher, 128); // 128 bits = 8 bytes output

        mac.Init(new KeyParameter(ksmac));

        byte[] output = new byte[mac.GetMacSize()];
        mac.BlockUpdate(data, 0, data.Length);
        mac.DoFinal(output, 0);

        return output.Take(8).ToArray();
    }

    public static byte[] BuildTokenCommand(byte[] token)
    {
        // Token ska vara 8 bytes
        if (token.Length != 8)
            throw new Exception("Token must be 8 bytes!");

        List<byte> command = new List<byte>();

        // Header
        command.Add(0x00);     // CLA (sista kommandot, ingen chaining)
        command.Add(0x86);     // INS (General Authenticate)
        command.Add(0x00);     // P1
        command.Add(0x00);     // P2

        // Beräkna längder
        byte tokenDataLength = 0x08;  // token är alltid 8 bytes
        byte dynamicAuthDataLength = (byte)(2 + tokenDataLength); // 85 + len + data
        byte totalLength = (byte)(2 + dynamicAuthDataLength); // 7C + len + inner data

        command.Add(totalLength); // Lc

        // Dynamic Authentication Data
        command.Add(0x7C);
        command.Add(dynamicAuthDataLength);

        // Token data
        command.Add(0x85);     // Tag för vår token
        command.Add(tokenDataLength);
        command.AddRange(token);

        // Le
        command.Add(0x00);

        return command.ToArray();
    }
}
