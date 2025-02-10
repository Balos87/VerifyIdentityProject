using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Asn1.TeleTrust;

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
        // 1. Generera privat nyckel (ett slumpmässigt tal mellan 1 och n-1)
        BigInteger n = domainParameters.N; // Kurvans ordning
        BigInteger privateKey;
        do
        {
            privateKey = new BigInteger(n.BitLength, secureRandom);
        }
        while (privateKey.CompareTo(BigInteger.One) < 0 || privateKey.CompareTo(n) >= 0);

        // 2. Skapar publik nyckel. (privat nyckel * G)
        ECPoint publicKey = domainParameters.G.Multiply(privateKey);

        return new ECDHKeyPair
        {
            PrivateKey = privateKey,
            PublicKey = publicKey
        };
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

     //1.brainpoolP384r1 parametrar  2.Vår privata nyckel från förr 3.Chippets publika nyckel som vi just extraherade
    public static ECPoint CalculateH( ECDomainParameters curveParameters, BigInteger ourPrivateKey, byte[] chipPublicKeyBytes)            
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
}

//// Exempel på användning:
//public void DemonstrationUsage()
//{
//    // Sätt upp domänparametrar
//    var domainParameters = ECDHKeyGenerator.SetupBrainpoolP384r1();
//    var keyGenerator = new ECDHKeyGenerator(domainParameters);

//    // Generera nyckelpar
//    var keyPair = keyGenerator.GenerateKeyPair();

//    // Konvertera publik nyckel till byte array (för att skicka till chip)
//    byte[] publicKeyBytes = ECDHKeyGenerator.PublicKeyToBytes(keyPair.PublicKey);

//    // När du får tillbaka chippets publika nyckel kan du konvertera den tillbaka
//    ECPoint chipPublicKey = keyGenerator.BytesToPublicKey(publicKeyBytes);
//}