using Android.Nfc.Tech;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using static Android.Renderscripts.ScriptGroup;

public class SecureMessage3
{
    private readonly IsoDep _isoDep;
    private readonly byte[] _ksEnc;
    private readonly byte[] _ksMac;
    private byte[] _ssc;

    public SecureMessage3(byte[] ksEnc, byte[] ksMac, IsoDep isoDep)
    {
        _ksEnc = ksEnc;
        _ksMac = ksMac;
        _isoDep = isoDep;
        _ssc = new byte[16];
    }

    public bool PerformSecureMessage()
    {
        Console.WriteLine("-------------------------------------Secure Messaging started..");
        try
        {
            byte[] plainSelectAPDU = new byte[]
            {
                0x00,                   // CLA
                0xA4,                   // INS (SELECT)
                0x04,                   // P1 (Select by name)
                0x0C,                   // P2 (No response data)
                0x07,                   // Lc (Length of data)
                0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01,0x00  // ePassport AID
            };

            byte[] protectedApdu = BuildSecureAPDU(plainSelectAPDU);
            Console.WriteLine($"plainSelectAPDU selectApdu: {BitConverter.ToString(plainSelectAPDU)}");
            Console.WriteLine($"Protected selectApdu: {BitConverter.ToString(protectedApdu)}");

            byte[] response = _isoDep.Transceive(plainSelectAPDU);

            if (!IsSuccessfulResponse(response))
            {
                Console.WriteLine($"Failed to select passport application. Response:{BitConverter.ToString(response)}");
                return false;
            }

            Console.WriteLine($"Application selected. Response:{BitConverter.ToString(response)}");
            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            return false;
        }
    }

    public byte[] BuildSecureAPDU(byte[] command)
    {
        //--------------------------------------------------------------------  1. Mask class byte and pad command header
        byte[] cmdHeader = new byte[]
        {
        0x0C, 0xA4, 0x04, 0x0C,  // CLA, INS, P1, P2
        0x80, 0x00, 0x00, 0x00,  // Padding
        };
        Console.WriteLine($"cmdHeader: {BitConverter.ToString(cmdHeader)}");

        //--------------------------------------------------------------------  1.1 Pad data (ePassport AID)
        byte[] data = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
        byte[] paddedData = PadDataForAES(data);
        Console.WriteLine($"Padded Data: {BitConverter.ToString(paddedData)}");

        //--------------------------------------------------------------------  1.2 Encrypt data with KSEnc

        byte[] encryptedData = EncryptDataAES(paddedData, _ksEnc, _ssc);
        Console.WriteLine($"Encrypted Data with KsEnc: {BitConverter.ToString(encryptedData)}");

        //--------------------------------------------------------------------  1.3 Build DO'87'
        byte[] DO87 = BuildDO87(encryptedData);
        Console.WriteLine($"DO87: {BitConverter.ToString(DO87)}");

        //--------------------------------------------------------------------  1.4 Concatenate CmdHeader and DO'87'
        //--------------------------------------------------------------------  1.4 Concatenate CmdHeader and DO'87'
        byte[] headerWithoutPadding = new byte[] { 0x0C, 0xA4, 0x04, 0x0C };
        byte[] M = headerWithoutPadding.Concat(DO87).ToArray();
        //byte[] M = cmdHeader.Concat(DO87).ToArray();
        //Console.WriteLine($"M: {BitConverter.ToString(M)}");

        //--------------------------------------------------------------------  2. Compute MAC

        //--------------------------------------------------------------------  2.1 Increment SSC
        IncrementSSC();
        Console.WriteLine($"SSC incremented: {BitConverter.ToString(_ssc)}");

        //--------------------------------------------------------------------  2.2 Concatenate SSC + M
        byte[] N = _ssc.Concat(M).ToArray();
        Console.WriteLine($"N: {BitConverter.ToString(N)}");

        //--------------------------------------------------------------------  2.3 Compute CMAC
        byte[] CC = ComputeCMAC(N, _ksMac);
        Console.WriteLine($"CC (MAC over N with KSMAC): {BitConverter.ToString(CC)}");

        //--------------------------------------------------------------------  3. Build DO'8E'
        byte[] DO8E = BuildDO8E(CC);
        Console.WriteLine($"DO8E: {BitConverter.ToString(DO8E)}");

        //--------------------------------------------------------------------  4. Construct protected APDU
        return ConstructFinalAPDU(cmdHeader.Take(4).ToArray(), DO87, DO8E);
    }

    private byte[] PadDataForAES(byte[] data)
    {
        int blockSize = 16;
        int paddedLength = ((data.Length + blockSize) / blockSize) * blockSize;
        byte[] paddedData = new byte[paddedLength];
        Array.Copy(data, paddedData, data.Length);
        paddedData[data.Length] = 0x80; // Längdbyte
        return paddedData;
    }

    private byte[] EncryptDataAES(byte[] paddedData, byte[] KSEnc, byte[] SSC)
    {
        Console.WriteLine($"SSC before calculating IV: {BitConverter.ToString(SSC)}");
        var iv = CalculateIV(); // Detta krypterar redan SSC för att skapa IV
        Console.WriteLine($"calculated IV: {BitConverter.ToString(iv)}");

        using (Aes aes = Aes.Create())
        {
            aes.Key = KSEnc;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            aes.IV = iv;  // Använd det beräknade IV:et

            using (var encryptor = aes.CreateEncryptor())
            {
                return encryptor.TransformFinalBlock(paddedData, 0, paddedData.Length);
            }
        }
    }
    private byte[] CalculateIV()
    {
        using (var aes = Aes.Create())
        {
            aes.Key = _ksEnc;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.None;
            byte[] zeroIV = new byte[16]; // Initial IV of zeros

            using (var encryptor = aes.CreateEncryptor(_ksEnc, zeroIV))
            {
                return encryptor.TransformFinalBlock(_ssc, 0, _ssc.Length);
            }
        }
    }

    private byte[] ComputeCMAC(byte[] data, byte[] KSMac)
    {
        IMac mac = MacUtilities.GetMac("AESCMAC");
        mac.Init(new KeyParameter(KSMac));
        mac.BlockUpdate(data, 0, data.Length);
        byte[] fullMac = new byte[mac.GetMacSize()];
        mac.DoFinal(fullMac, 0);
        return fullMac.Take(8).ToArray(); // Return first 8 bytes as specified
    }

    private byte[] BuildDO87(byte[] encryptedData)
    {
        List<byte> DO87 = new List<byte>
    {
        0x87,                                    // Tag
        (byte)(encryptedData.Length + 1),       // Length
        0x01                                    // Padding indicator
    };
        DO87.AddRange(encryptedData);
        return DO87.ToArray();
    }

    private byte[] BuildDO8E(byte[] mac)
    {
        List<byte> DO8E = new List<byte>
    {
        0x8E,       // Tag
        0x08        // Length (MAC is always 8 bytes)
    };
        DO8E.AddRange(mac);
        return DO8E.ToArray();
    }

    private byte[] ConstructFinalAPDU(byte[] header, byte[] DO87, byte[] DO8E)
    {
        List<byte> protectedAPDU = new List<byte>();
        protectedAPDU.AddRange(header);                         // Command header
        protectedAPDU.Add((byte)(DO87.Length + DO8E.Length));  // Lc
        protectedAPDU.AddRange(DO87);                          // Protected data
        protectedAPDU.AddRange(DO8E);                          // MAC
        protectedAPDU.Add(0x00);                               // Le
        return protectedAPDU.ToArray();
    }

    private void IncrementSSC()
    {
        for (int i = _ssc.Length - 1; i >= 0; i--)
        {
            if (++_ssc[i] != 0)
                break;
        }
    }

    private byte[] PadData(byte[] data)
    {
        // ISO/IEC 7816-4 padding
        int padLength = 16 - (data.Length % 16);
        byte[] paddedData = new byte[data.Length + padLength];
        Buffer.BlockCopy(data, 0, paddedData, 0, data.Length);
        paddedData[data.Length] = 0x80;
        return paddedData;
    }

    private byte[] EncryptData(byte[] paddedData)
    {
        // Generate IV by encrypting SSC
        using var aes = Aes.Create();
        aes.Key = _ksEnc;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;

        // First encrypt SSC to get IV
        byte[] iv = new byte[16];
        using (var encryptor = aes.CreateEncryptor(_ksEnc, new byte[16]))
        {
            encryptor.TransformBlock(_ssc, 0, _ssc.Length, iv, 0);
        }

        // Then encrypt the actual data with the generated IV
        aes.IV = iv;
        using var encryptor2 = aes.CreateEncryptor();
        return encryptor2.TransformFinalBlock(paddedData, 0, paddedData.Length);
    }

    private byte[] BuildMacInput(byte cla, byte ins, byte p1, byte p2, byte[] protectedData)
    {
        List<byte> macInput = new List<byte>();
        macInput.AddRange(_ssc);                    // Add SSC
        macInput.Add(cla);                          // Add header
        macInput.Add(ins);
        macInput.Add(p1);
        macInput.Add(p2);
        macInput.AddRange(protectedData);           // Add protected data fields
        return macInput.ToArray();
    }

    private byte[] CalculateCMAC(byte[] input)
    {
        // Use BouncyCastle for CMAC
        IMac mac = MacUtilities.GetMac("AESCMAC");
        mac.Init(new KeyParameter(_ksMac));
        mac.BlockUpdate(input, 0, input.Length);
        byte[] fullMac = new byte[mac.GetMacSize()];
        mac.DoFinal(fullMac, 0);

        // Return only first 8 bytes as specified
        return fullMac.Take(8).ToArray();
    }
    private static bool IsSuccessfulResponse(byte[] response)
    {
        return response.Length >= 2 && response[^2] == 0x90 && response[^1] == 0x00;
    }

    // Example usage for SELECT command
    public byte[] BuildSelectEPassportAPDU()
    {
        byte[] plainSelectAPDU = new byte[]
        {
            0x00,                   // CLA
            0xA4,                   // INS (SELECT)
            0x04,                   // P1 (Select by name)
            0x0C,                   // P2 (No response data)
            0x07,                   // Lc (Length of data)
            0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01  // ePassport AID
        };

        return BuildSecureAPDU(plainSelectAPDU);
    }
}