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

    // Help method to set up the domain parameters for brainpoolP384r1 -- Not in use!
    public static ECDomainParameters SetupBrainpoolP384r1()
    {
        // Getting the standard curve parameters for brainpoolP384r1 
        X9ECParameters curve = TeleTrusTNamedCurves.GetByName("brainpoolP384r1");

        // Create a domain parameter from the curve parameters
        return new ECDomainParameters(
            curve.Curve,          // Curve
            curve.G,              // Generate point G
            curve.N,              // Order n
            curve.H,              // Cofactor
            curve.GetSeed()       // Curveseed (Can be null)
        );
    }

    public ECDHKeyPair GenerateKeyPair()
    {
        // 1. Generate private key with BouncyCastle's built-in method
        BigInteger privateKey = BigIntegers.CreateRandomInRange(
            BigInteger.One,  // Lowest allowed value (1)
            domainParameters.N.Subtract(BigInteger.One),  // Highest allowed value (n-1)
            secureRandom  // Our secure random number generator
        );

        // 2. Create public key = privateKey * G and normalize it
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
        // Check if point is on the curve
        if (!publicKey.IsValid())
            return false;

        // Check if point is in the correct order
        if (!publicKey.Multiply(domainParams.N).IsInfinity)
            return false;

        //Check if point is not infinity
        if (publicKey.IsInfinity)
            return false;
        
        return true;
    }

    public static byte[] PublicKeyToBytes(ECPoint publicKey)
    {
        // Convert to uncompressed format (0x04 || x || y)
        return publicKey.GetEncoded(false);
    }

    // Method to build APDU that sends our public key to the chip
    public static byte[] BuildMapNonceCommand(byte[] publicKey)
    {
        // Counting the length
        byte mappingDataLength = (byte)publicKey.Length;  // len2
        byte dynamicAuthDataLength = (byte)(2 + mappingDataLength); // len1: 81 + len + data
        byte totalLength = (byte)(2 + dynamicAuthDataLength); // Lc: 7C + len + inner data

        // Build command
        List<byte> command = new List<byte>();

        // Header
        command.Add(0x10);     // CLA (Command chaining)
        command.Add(0x86);     // INS (General Authenticate)
        command.Add(0x00);     // P1
        command.Add(0x00);     // P2
        command.Add(totalLength); // Lc

        // Dynamic Authentication Data
        command.Add(0x7C);     // Tag for Dynamic Authentication Data
        command.Add(dynamicAuthDataLength);

        // Mapping Data
        command.Add(0x81);     // Tag for Mapping Data
        command.Add(mappingDataLength);

        // Adding the public key (which already contains 04 || x || y)
        command.AddRange(publicKey);

        // Le
        command.Add(0x00);

        return command.ToArray();
    }

    public static byte[] ExtractPublicKeyFromResponse(byte[] response)
    {
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
            // Create BigInteger from decryptedNonce
            var s = new Org.BouncyCastle.Math.BigInteger(1, decryptedNonce);
            s = s.Mod(curveParams.N);

            //  Console.WriteLine($"Nonce (s): {s.ToString(16)}");
            //  Console.WriteLine($"Curve order (N): {curveParams.N.ToString(16)}");

            // Validate that s is within the valid range: 1 ≤ s ≤ n-1
            if (s.SignValue <= 0 || s.CompareTo(curveParams.N.Subtract(Org.BouncyCastle.Math.BigInteger.One)) >= 0)
                throw new Exception("Nonce value is out of range for the curve domain.");

            return (s);
        }
        catch (Exception e)
        {
            throw new Exception("Could not convert S to BigInteger", e);
        }
    }

    public static ECPoint CalculateH(ECDomainParameters curveParameters, BigInteger ourPrivateKey, byte[] chipPublicKeyBytes)
    {
        // Convert chip public key from bytes to ECPoint
        ECPoint chipPublicKey = curveParameters.Curve.DecodePoint(chipPublicKeyBytes); 

        if (!chipPublicKey.IsValid())
            throw new ArgumentException("Invalid public key from chip");

        // Calculate H = chipPublicKey * ourPrivateKey
        ECPoint H = chipPublicKey.Multiply(ourPrivateKey);

        // Validate result
        if (H.IsInfinity)
            throw new InvalidOperationException("Calculation resulted in invalid point");
        return H;
    }

    public ECDHKeyPair GenerateKeyPairWithGTilde(ECPoint gTilde)
    {
        // 1. Generate a private key (a random number between 1 and n-1)
        BigInteger n = domainParameters.N; //curve order
        BigInteger privateKey;
        do
        {
            privateKey = new BigInteger(n.BitLength, secureRandom);
        }
        while (privateKey.CompareTo(BigInteger.One) < 0 || privateKey.CompareTo(n) >= 0);

        // 2. Create public key = privateKey * G̃
        ECPoint publicKey = gTilde.Multiply(privateKey);

        return new ECDHKeyPair
        {
            PrivateKey = privateKey,
            PublicKey = publicKey
        };
    }

    public static byte[] BuildKeyAgreementCommandGTilde(byte[] publicKey)
    {
        // Counting the length
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
        command.Add(0x83);     // Tag for key agreement (note: 0x83 instead of 0x81)
        command.Add(mappingDataLength);

        command.AddRange(publicKey);

        // Le
        command.Add(0x00);

        return command.ToArray();
    }

    public static byte[] ExtractGTildePublicKeyFromResponse(byte[] response)
    {
        if (response == null || response.Length < 7)
            throw new Exception("response is null or to short!");

        if (response[response.Length - 2] != 0x90 || response[response.Length - 1] != 0x00)
            throw new Exception("response is not 90-00!");

        int index = 0;

        if (response[index++] != 0x7C)
            throw new Exception("response is missing 7C start-tag!");
        index++;

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
        // We only need x-coordinate from K
        var normalizedK = K.Normalize();
        byte[] kBytes = normalizedK.AffineXCoord.GetEncoded();
        // Console.WriteLine($"x kBytes: {BitConverter.ToString(kBytes)}");
        //  Console.WriteLine($"x kBytes.Length: {kBytes.Length}");

        // Create counter as 32-bit big-endian
        byte[] counterBytes = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);

        // Concatenate K || counter
        byte[] concatenated = new byte[kBytes.Length + 4];
        kBytes.CopyTo(concatenated, 0);
        counterBytes.CopyTo(concatenated, kBytes.Length);

        // Calculate SHA-256
        var sha256 = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
        byte[] hash = new byte[sha256.GetDigestSize()];
        sha256.BlockUpdate(concatenated, 0, concatenated.Length);
        sha256.DoFinal(hash, 0);

        return hash;  // return 32-byte (256-bit) key
    }

    public static byte[] BuildAuthenticationTokenInput(byte[] publicKey, byte[] oid)
    {
        List<byte> data = new List<byte>();

        // Count the total length (OID length + public key length + extra bytes for tags and lengths)
        int totalLength = 2 + oid.Length + 2 + publicKey.Length;  // 2 bytes for each tagg+length combo

        // Public Key Data tag (7F49)
        data.Add(0x7F);
        data.Add(0x49);
        data.Add((byte)totalLength);  // Dynamic length

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
        if (token.Length != 8)
            throw new Exception("Token must be 8 bytes!");

        List<byte> command = new List<byte>();

        // Header
        command.Add(0x00);     // CLA (no chaining)
        command.Add(0x86);     // INS (General Authenticate)
        command.Add(0x00);     // P1
        command.Add(0x00);     // P2

        // Counting the length
        byte tokenDataLength = 0x08;  // Token is always 8 bytes
        byte dynamicAuthDataLength = (byte)(2 + tokenDataLength); // 85 + len + data
        byte totalLength = (byte)(2 + dynamicAuthDataLength); // 7C + len + inner data

        command.Add(totalLength); // Lc

        // Dynamic Authentication Data
        command.Add(0x7C);
        command.Add(dynamicAuthDataLength);

        // Token data
        command.Add(0x85);     // Tag for our token
        command.Add(tokenDataLength);
        command.AddRange(token);

        // Le
        command.Add(0x00);

        return command.ToArray();
    }
}
