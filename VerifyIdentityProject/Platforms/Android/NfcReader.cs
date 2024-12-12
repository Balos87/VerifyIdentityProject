using Android.Nfc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using VerifyIdentityProject.Resources.Interfaces;
using Android.App;
using Android.Nfc.Tech;
using VerifyIdentityProject.Helpers;
using System.Security.Cryptography;

namespace VerifyIdentityProject.Platforms.Android
{
    internal class NfcReader : INfcReader
    {
        private NfcAdapter _nfcAdapter;
        private Activity _activity;

        public NfcReader()
        {
            _activity = Platform.CurrentActivity!;
            _nfcAdapter = NfcAdapter.GetDefaultAdapter(_activity);
        }

        public void StartListening()
        {
            if (_nfcAdapter == null || !_nfcAdapter.IsEnabled)
            {
                Console.WriteLine("NFC not supported or not enabled.");
                return;
            }

            _nfcAdapter.EnableReaderMode(_activity, new NfcReaderCallback(), NfcReaderFlags.NfcA | NfcReaderFlags.SkipNdefCheck, null);
        }

        public void StopListening()
        {
            _nfcAdapter.DisableReaderMode(_activity);
        }
    }

    public class NfcReaderCallback : Java.Lang.Object, NfcAdapter.IReaderCallback
    {
        private byte[] _kSEnc;
        private byte[] _kSMac;
        public void OnTagDiscovered(Tag tag)
        {
            try
            {
                IsoDep isoDep = IsoDep.Get(tag);
                if (isoDep != null)
                {
                    isoDep.Connect();

                    //byte[] selectApdu = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01, 0x00 };
                    byte[] selectApdu = new byte[] {
                        0x00, // CLA
                        0xA4, // INS
                        0x04, // P1
                        0x0C, // P2 (Corrected)
                        0x07, // Lc (Length of AID)
                        0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 // AID
                        // Removed extra 0x00 byte
                    };

                    byte[] response = isoDep.Transceive(selectApdu);
                    Console.WriteLine($"Select APDU: {BitConverter.ToString(selectApdu)}");
                    Console.WriteLine($"Select Response: {BitConverter.ToString(response)}");
                    if (!IsSuccessfulResponse(response))
                    {
                        Console.WriteLine("Failed to select passport application.");
                        isoDep.Close();
                        return;
                    }

                    Console.WriteLine("Application selected.");

                    Console.WriteLine("Performing BAC...");
                    string passportNumber = "AA3374113";
                    string birthDate = "871118";
                    string expiryDate = "280302";

                    var (KEnc, KMac) = BacHelper.GenerateBacKeys(passportNumber, birthDate, expiryDate);
                    Console.WriteLine($"KEnc: {BitConverter.ToString(KEnc)}");
                    Console.WriteLine($"KMac: {BitConverter.ToString(KMac)}");

                    if (KEnc == null || KMac == null || KEnc.Length != 16 || KMac.Length != 16)
                    {
                        Console.WriteLine("Invalid BAC keys derived.");
                        isoDep.Close();
                        return;
                    }

                    if (!PerformBacAuthentication(isoDep, KEnc, KMac))
                    {
                        Console.WriteLine("BAC authentication failed.");
                        isoDep.Close();
                        return;
                    }

                    Console.WriteLine("BAC authentication succeeded!");

                    Console.WriteLine("Accessing DG1...");

                    //byte[] selectDG1Command = new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E };
                    //byte[] selectDG1Response = isoDep.Transceive(selectDG1Command);

                    byte[] selectDG1Command = BuildSecureReadCommand(0x01);
                    byte[] selectDG1Response = isoDep.Transceive(selectDG1Command);

                    if (!IsSuccessfulResponse(selectDG1Response))
                    {
                        Console.WriteLine("Failed to select DG1 file.");
                        isoDep.Close();
                        return;
                    }
                    Console.WriteLine("DG1 file selected.");

                    byte[] readCommand = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x00 };
                    byte[] dg1Response = isoDep.Transceive(readCommand);

                    if (!IsSuccessfulResponse(dg1Response))
                    {
                        Console.WriteLine("Failed to read DG1 data.");
                        isoDep.Close();
                        return;
                    }

                    byte[] dg1Data = dg1Response.Take(dg1Response.Length - 2).ToArray();
                    Console.WriteLine($"DG1 Data (raw): {BitConverter.ToString(dg1Data)}");

                    DecodePassportData(dg1Data);

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during NFC processing: {ex.Message}");
            }
        }

        private byte[] BuildMutualAuthCommand(byte[] challenge, byte[] KEnc, byte[] KMac)
        {
            Console.WriteLine($"Challenge (S): {BitConverter.ToString(challenge)}");

            byte[] encryptedChallenge = EncryptWithKEnc(challenge, KEnc);
            Console.WriteLine($"Encrypted Challenge (eS): {BitConverter.ToString(encryptedChallenge)}");

            byte[] mac = ComputeMac(encryptedChallenge, KMac);
            Console.WriteLine($"MAC: {BitConverter.ToString(mac)}");

            byte[] mutualAuthCommand = encryptedChallenge.Concat(mac).ToArray();
            Console.WriteLine($"Mutual Authentication Command: {BitConverter.ToString(mutualAuthCommand)}");

            return mutualAuthCommand;
        }

        private byte[] BuildApduCommand(byte cla, byte ins, byte p1, byte p2, byte[] data)
        {
            byte lc = (byte)(data.Length & 0xFF); // Safeguard the length to fit within a single byte

            // Log the APDU fields
            Console.WriteLine($"APDU Fields - CLA: {cla:X2}, INS: {ins:X2}, P1: {p1:X2}, P2: {p2:X2}, Lc: {lc:X2}");

            return new byte[] { cla, ins, p1, p2, lc }
                .Concat(data)
                .ToArray();
        }

        private bool PerformBacAuthentication(IsoDep isoDep, byte[] KEnc, byte[] KMac)
        {
            try
            {
                // Step 1: Get the random challenge (RND.IC)
                byte[] challengeCommand = new byte[] { 0x00, 0x84, 0x00, 0x00, 0x08 };
                byte[] challengeResponse = isoDep.Transceive(challengeCommand);
                Console.WriteLine($"Challenge Response: {BitConverter.ToString(challengeResponse)}");

                if (!IsSuccessfulResponse(challengeResponse))
                {
                    Console.WriteLine("Failed to get challenge response.");
                    return false;
                }

                byte[] rndIC = challengeResponse.Take(8).ToArray();
                Console.WriteLine($"Random IC: {BitConverter.ToString(rndIC)}");

                // Step 2: Generate random RND.IFD and K.IFD
                var (rndIFD, kIFD) = GenerateRandoms();
                Console.WriteLine($"Random IFD: {BitConverter.ToString(rndIFD)}");
                Console.WriteLine($"K.IFD: {BitConverter.ToString(kIFD)}");

                // Step 3: Concatenate S = RND.IFD || RND.IC || K.IFD
                byte[] s = rndIFD.Concat(rndIC).Concat(kIFD).ToArray();
                Console.WriteLine($"S (concatenated): {BitConverter.ToString(s)}");

                // Step 4-5: Use BuildMutualAuthCommand to construct the mutual authentication command
                byte[] mutualAuthCommandData = BuildMutualAuthCommand(s, KEnc, KMac);
                Console.WriteLine($"Mutual Authentication Command Data: {BitConverter.ToString(mutualAuthCommandData)}");

                // Step 6: Wrap in APDU format //TEST P2 = 0x0C instead of 0x00.
                byte[] mutualAuthCommand = BuildApduCommand(0x00, 0x82, 0x00, 0x00, mutualAuthCommandData);

                Console.WriteLine($"Final APDU Command: {BitConverter.ToString(mutualAuthCommand)}");

                // Step 7: Send APDU to chip
                byte[] mutualAuthResponse = isoDep.Transceive(mutualAuthCommand);

                Console.WriteLine($"Raw Mutual Authentication Response: {BitConverter.ToString(mutualAuthResponse)}");

                // Check response status bytes
                if (mutualAuthResponse.Length >= 2)
                {
                    byte sw1 = mutualAuthResponse[^2];
                    byte sw2 = mutualAuthResponse[^1];
                    Console.WriteLine($"Response Status Bytes: SW1={sw1:X2}, SW2={sw2:X2}");

                    // Check if the response indicates success
                    if (sw1 != 0x90 || sw2 != 0x00)
                    {
                        Console.WriteLine("Mutual authentication failed with status bytes.");
                        return false;
                    }
                }
                else
                {
                    Console.WriteLine("Mutual authentication failed: Response is too short.");
                    return false;
                }

                if (!IsSuccessfulResponse(mutualAuthResponse))
                {
                    Console.WriteLine("Mutual authentication failed.");
                    return false;
                }

                // Step 7: Derive session keys
                var (KSEnc, KSMac) = BacHelper.DeriveSessionKeys(KEnc, KMac, rndIFD, rndIC);
                Console.WriteLine($"Session Keys:\nKSEnc: {BitConverter.ToString(KSEnc)}\nKSMac: {BitConverter.ToString(KSMac)}");

                // Store the session keys
                _kSEnc = KSEnc;
                _kSMac = KSMac;

                // Use KSEnc and KSMac for secure messaging
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"BAC authentication error: {ex.Message}");
                return false;
            }
        }

        private (byte[] rndIFD, byte[] kIFD) GenerateRandoms()
        {
            byte[] rndIFD = new byte[8];
            byte[] kIFD = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(rndIFD);
                rng.GetBytes(kIFD);
            }
            Console.WriteLine($"Generated rndIFD: {BitConverter.ToString(rndIFD)}");
            Console.WriteLine($"Generated kIFD: {BitConverter.ToString(kIFD)}");
            return (rndIFD, kIFD);
        }

        private byte[] BuildSecureReadCommand(int fileId, int offset = 0, int length = 256)
        {
            if (_kSEnc == null || _kSMac == null)
            {
                throw new InvalidOperationException("Session keys are not initialized. Perform BAC authentication first.");
            }
            Console.WriteLine($"Using KSEnc: {BitConverter.ToString(_kSEnc)}");
            Console.WriteLine($"Using KSMac: {BitConverter.ToString(_kSMac)}");

            byte[] command = new byte[] { 0x0C, 0xB0, (byte)((offset >> 8) & 0xFF), (byte)(offset & 0xFF), (byte)length };
            byte[] encryptedCommand = EncryptWithKEnc(command, _kSEnc);
            byte[] mac = ComputeMac(encryptedCommand, _kSMac);

            Console.WriteLine($"Command Before Encryption: {BitConverter.ToString(command)}");
            Console.WriteLine($"Encrypted Command: {BitConverter.ToString(encryptedCommand)}");
            Console.WriteLine($"MAC: {BitConverter.ToString(mac)}");


            return encryptedCommand.Concat(mac).ToArray();
        }

        private byte[] PadToBlockSize(byte[] data, int blockSize)
        {
            int paddedLength = ((data.Length + blockSize - 1) / blockSize) * blockSize;
            byte[] paddedData = new byte[paddedLength];
            Array.Copy(data, paddedData, data.Length);
            return paddedData; // Padded with zeros by default
        }

        private byte[] EncryptWithKEnc(byte[] data, byte[] KEnc)
        {
            Console.WriteLine($"Original data length: {data.Length}");
            Console.WriteLine($"Original data: {BitConverter.ToString(data)}");

            data = PadToBlockSize(data, 16);

            Console.WriteLine($"Padded data length: {data.Length}");
            Console.WriteLine($"Padded data: {BitConverter.ToString(data)}");

            // Ensure input data length is a multiple of the block size
            if (data.Length % 16 != 0)
            {
                Console.WriteLine($"Data before padding: {BitConverter.ToString(data)}");
                data = PadToBlockSize(data, 16); // Pad to 16-byte blocks
                Console.WriteLine($"Data after padding: {BitConverter.ToString(data)}");
            }

            using (var des = TripleDES.Create())
            {
                des.Key = KEnc;
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.None;

                using (var encryptor = des.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }
        private byte[] ComputeMac(byte[] data, byte[] KMac)
        {
            using (var hmac = new HMACSHA1(KMac))
            {
                return hmac.ComputeHash(data).Take(8).ToArray();
            }
        }

        private bool IsSuccessfulResponse(byte[] response)
        {
            return response.Length >= 2 && response[^2] == 0x90 && response[^1] == 0x00;
        }

        private void DecodePassportData(byte[] data)
        {
            var parser = new Asn1DerParser();
            parser.Parse(data);
        }
    }

    public class Asn1DerParser
    {
        public void Parse(byte[] data)
        {
            int index = 0;

            while (index < data.Length)
            {
                if (index + 2 > data.Length)
                {
                    Console.WriteLine("Malformed ASN.1 data.");
                    break;
                }

                byte tag = data[index++];
                Console.WriteLine($"Tag: {tag:X2}");

                int length = ReadLength(data, ref index);
                Console.WriteLine($"Length: {length}");

                if (index + length > data.Length)
                {
                    Console.WriteLine("Invalid length specified.");
                    break;
                }

                byte[] value = data.Skip(index).Take(length).ToArray();
                index += length;

                Console.WriteLine($"Value: {BitConverter.ToString(value)}");

                if (tag == 0x61)
                {
                    Console.WriteLine("DG1 Sequence:");
                    Parse(value);
                }
                else if (tag == 0x5F1F)
                {
                    string mrz = Encoding.UTF8.GetString(value);
                    Console.WriteLine("Decoded MRZ:");
                    Console.WriteLine(mrz);
                }
                else if ((tag & 0x20) == 0x20)
                {
                    Console.WriteLine("Parsing constructed type...");
                    Parse(value);
                }
            }
        }

        private int ReadLength(byte[] data, ref int index)
        {
            int length = data[index++];
            if ((length & 0x80) == 0x80)
            {
                int lengthBytes = length & 0x7F;
                length = 0;
                for (int i = 0; i < lengthBytes; i++)
                {
                    length = (length << 8) | data[index++];
                }
            }
            return length;
        }
    }
}