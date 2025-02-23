using System;
using System.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

public class SecureMessagingPACE
{
    private byte[] KSEnc; // Krypteringsnyckel
    private byte[] KSMac; // MAC-nyckel
    private byte[] SSC;   // Send Sequence Counter (börjar på 16 bytes nollor)

    public SecureMessagingPACE(byte[] ksEnc, byte[] ksMac)
    {
        KSEnc = ksEnc;
        KSMac = ksMac;
        SSC = new byte[16]; // Initieras med 16 bytes av nollor
    }

    public byte[] SecureApduCommand(byte[] cmdHeader, byte[] data)
    {
        // 1. Öka SSC
        IncrementSSC();
        Console.WriteLine("SSC: " + BitConverter.ToString(SSC));

        byte[] maskedCmdHeader = cmdHeader.Concat(new byte[] { 0x80, 0x00, 0x00, 0x00 }).ToArray();
        Console.WriteLine("maskedCmdHeader: " + BitConverter.ToString(maskedCmdHeader));


        // 2. Beräkna IV = AES-ENC(KSEnc, SSC)
        byte[] IV = EncryptSSC();
        Console.WriteLine("IV: " + BitConverter.ToString(IV));

        // 3. Kryptera data med AES-CBC
        byte[] encryptedData = data.Length > 0 ? EncryptData(data, IV) : new byte[0];

        // 4. Bygg DO87
        byte[] DO87 = encryptedData.Length > 0 ? BuildDO87(encryptedData) : new byte[0];

        // 5. Bygg DO97 (om Le används)
        byte[] DO97 = new byte[0]; // Lägg till om Le förväntas

        // 6. Bygg sträng för MAC
        byte[] messageToMac = SSC.Concat(maskedCmdHeader).Concat(DO87).Concat(DO97).ToArray();
        Console.WriteLine("messageToMac: " + BitConverter.ToString(messageToMac));

        // 7. Beräkna MAC med KSMac
        byte[] mac = ComputeMAC(messageToMac);
        Console.WriteLine("mac: " + BitConverter.ToString(mac));

        // 8. Bygg DO8E
        byte[] DO8E = BuildDO8E(mac);

        // 9. Slutgiltigt APDU-kommando
        return cmdHeader.Concat(DO87).Concat(DO97).Concat(DO8E).ToArray();
    }


    private void IncrementSSC()
    {
        for (int i = SSC.Length - 1; i >= 0; i--)
        {
            if (++SSC[i] != 0) break;
        }
    }

    private byte[] EncryptData(byte[] data, byte[] IV)
    {
        // 1. Lägg till padding enligt ISO 9797-1 Padding Method 2
        data = ApplyPadding(data);
        Console.WriteLine("padded data: " + BitConverter.ToString(data));


        // 3. AES-CBC Kryptering med IV = AES(KSEnc, SSC)
        var cipher = CipherUtilities.GetCipher("AES/CBC/NoPadding");
        cipher.Init(true, new ParametersWithIV(new KeyParameter(KSEnc), IV));
        return cipher.DoFinal(data);
    }

    // Lägg till padding till data så att den blir multipel av 16 bytes
    private byte[] ApplyPadding(byte[] data)
    {
        int blockSize = 16;
        int paddingLength = blockSize - (data.Length % blockSize);
        byte[] paddedData = new byte[data.Length + paddingLength];
        Array.Copy(data, paddedData, data.Length);

        // ISO 9797-1 Padding Method 2: 0x80 följt av 0x00
        paddedData[data.Length] = 0x80;
        for (int i = data.Length + 1; i < paddedData.Length; i++)
        {
            paddedData[i] = 0x00;
        }

        return paddedData;
    }

    // Kryptera SSC med KSEnc för att få IV
    private byte[] EncryptSSC()
    {
        var cipher = CipherUtilities.GetCipher("AES/ECB/NoPadding");
        cipher.Init(true, new KeyParameter(KSEnc));
        return cipher.DoFinal(SSC);
    }


    private byte[] ComputeMAC(byte[] data)
    {
        var mac = new CMac(new AesEngine(), 128);
        mac.Init(new KeyParameter(KSMac));

        byte[] result = new byte[mac.GetMacSize()];
        mac.BlockUpdate(data, 0, data.Length);
        mac.DoFinal(result, 0);
        return result.Take(8).ToArray(); // Vi tar bara de första 8 byten för MAC
    }

    private byte[] BuildDO87(byte[] encryptedData)
    {
        return new byte[] { 0x87, (byte)(encryptedData.Length + 1), 0x01 }
            .Concat(encryptedData).ToArray();
    }

    private byte[] BuildDO8E(byte[] mac)
    {
        return new byte[] { 0x8E, 0x08 }.Concat(mac).ToArray();
    }
}
