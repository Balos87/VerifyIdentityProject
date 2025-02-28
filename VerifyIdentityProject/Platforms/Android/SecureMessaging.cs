using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Android.Nfc.Tech;
using Android.Health.Connect.DataTypes.Units;

namespace VerifyIdentityProject.Platforms.Android
{
    /// <summary>
    /// This class implements secure messaging protection (and—by similar techniques—unprotection)
    /// following the ISO/IEC 7816 secure messaging (doc9303) style.
    /// It assumes that the session keys (KSenc and KSmac) and the send sequence counter (SSC)
    /// have already been derived (for example via BAC/PACE) and that AES/CBC with CMAC is used.
    /// </summary>
    public class SecureMessaging
    {
        // Session keys and SSC (SSC must be 8 bytes for our example)
        private byte[] ksEnc;
        private byte[] ksMac;
        private byte[] ssc;
        private readonly int blockSize; // for AES, 16 bytes

        /// <summary>
        /// Create a new secure messaging instance.
        /// </summary>
        /// <param name="ksEnc">Encryption key (e.g. 16 or 32 bytes for AES)</param>
        /// <param name="ksMac">MAC key (same length as needed for CMAC)</param>
        /// <param name="ssc">Initial Send Sequence Counter (8 bytes)</param>
        /// <param name="blockSize">Block size (16 for AES)</param>
        public SecureMessaging(byte[] ksEnc, byte[] ksMac, byte[] ssc)
        {
            if (ksEnc.Length != 32 || ksMac.Length != 32)
                throw new ArgumentException("Keys must be 32 bytes (AES-256).");

            this.ksEnc = ksEnc;
            this.ksMac = ksMac;
            this.ssc = ssc;
            this.blockSize = 16; // AES block size remains 16 bytes
        }

        /// <summary>
        /// Protect a command APDU.
        /// You must provide:
        ///   - a 4‐byte header (CLA, INS, P1, P2) – the “command header”
        ///   - an optional command body (data field) that will be encrypted (can be null or empty)
        ///   - an optional expected response length (Le) (as a byte array)
        /// The function returns the complete protected APDU.
        /// </summary>
        public byte[] ProtectCommand(byte[] apduHeader, byte[] apduData, byte[] le)
        {
            // 1. Increment SSC
            IncrementSSC();

            // 2. Mask the header (set CLA to 0x0C) and pad it.
            byte[] maskedHeader = MaskCommandHeader(apduHeader);

            // 3. If there is a command data field, build DO87.
            byte[] do87 = (apduData != null && apduData.Length > 0)
                ? BuildDO87(apduData)
                : null;

            // 4. If an expected response length is provided, build DO97.
            byte[] do97 = (le != null && le.Length > 0)
                ? BuildDO97(le)
                : null;

            // 5. Concatenate M = maskedHeader || do87 || do97.
            byte[] M = Concat(maskedHeader, do87, do97);

            // 6. For AES secure messaging, we typically use a “padded SSC”
            //    In the Swift example, for AES the padded SSC = 8 zero bytes concatenated with SSC.
            byte[] paddedSSC = Concat(new byte[8], ssc);

            // 7. Compute N = Pad( paddedSSC || M ) using ISO9797-1 Padding Method 2.
            byte[] N = PadIso9797Method2(Concat(paddedSSC, M), blockSize);

            // 8. Compute MAC (using AES-CMAC) over N.
            byte[] mac = ComputeAesCmac(ksMac, N);
            // If the MAC is longer than 8 bytes, take the first 8.
            if (mac.Length > 8)
                mac = mac.Take(8).ToArray();

            // 9. Build DO8E from the MAC.
            byte[] do8e = BuildDO8E(mac);

            // 10. Construct final protected APDU using the masked header's first 4 bytes instead of the original header.
            return ConstructProtectedAPDU(maskedHeader.Take(4).ToArray(), do87, do97, do8e, new byte[] { 0x00 });
        }


        // ---------------------
        // Helper Methods
        // ---------------------

        /// <summary>
        /// Mask the command header by setting the CLA to 0x0C and then pad the 4-byte header to a full block.
        /// </summary>
        private byte[] MaskCommandHeader(byte[] header)
        {
            if (header.Length < 4)
                throw new ArgumentException("Header must be at least 4 bytes.");
            byte[] masked = new byte[4];
            masked[0] = 0x0C; // Mask CLA to 0x0C
            Array.Copy(header, 1, masked, 1, 3);
            return PadIso9797Method2(masked, blockSize);
        }

        /// <summary>
        /// Build DO87: Tag 0x87, length, 0x01 (indicator for encrypted data) and then the encrypted (and padded) data.
        /// </summary>
        public byte[] BuildDO87(byte[] data)
        {
            // For AES, compute the IV as follows:
            // IV = AES-ECB(ksEnc, paddedSSC), where paddedSSC = 8 zero bytes concatenated with SSC.
            byte[] paddedSSC = Concat(new byte[8], ssc);
            byte[] iv = AesEcbEncrypt(ksEnc, paddedSSC);
            byte[] paddedData = PadIso9797Method2(data, blockSize);
            byte[] encryptedData = AesCbcEncrypt(ksEnc, paddedData, iv);

            // Build DO87: Tag (0x87), length, 0x01 and then encryptedData.
            byte[] do87 = new byte[3 + encryptedData.Length];
            do87[0] = 0x87;
            do87[1] = (byte)(1 + encryptedData.Length); // length field
            do87[2] = 0x01; // indicator for encrypted data
            Array.Copy(encryptedData, 0, do87, 3, encryptedData.Length);
            return do87;
        }

        /// <summary>
        /// Build DO97: Tag 0x97, length of Le field, and then Le.
        /// </summary>
        public byte[] BuildDO97(byte[] le)
        {
            byte[] do97 = new byte[2 + le.Length];
            do97[0] = 0x97;
            do97[1] = (byte)le.Length;
            Array.Copy(le, 0, do97, 2, le.Length);
            return do97;
        }

        /// <summary>
        /// Build DO8E: Tag 0x8E, length (should be 8), and then the MAC.
        /// </summary>
        public byte[] BuildDO8E(byte[] mac)
        {
            byte[] do8e = new byte[2 + mac.Length];
            do8e[0] = 0x8E;
            do8e[1] = (byte)mac.Length;
            Array.Copy(mac, 0, do8e, 2, mac.Length);
            return do8e;
        }

        /// <summary>
        /// Construct the final protected APDU.
        /// Here we assume that the final APDU is:
        ///   [Original header’s 4 bytes] || Lc || (DO87 || DO97 || DO8E) || Le (set to 0x00)
        /// </summary>
        public byte[] ConstructProtectedAPDU(byte[] header4, byte[] do87, byte[] do97, byte[] do8e, byte[] expectedLe)
        {
            byte[] dataField = Concat(do87, do97, do8e);
            byte lc = (byte)dataField.Length;
            byte[] protectedApdu = new byte[header4.Length + 1 + dataField.Length + expectedLe.Length];

            Array.Copy(header4, 0, protectedApdu, 0, header4.Length);
            protectedApdu[header4.Length] = lc;
            Array.Copy(dataField, 0, protectedApdu, header4.Length + 1, dataField.Length);

            // Correctly set Le
            Array.Copy(expectedLe, 0, protectedApdu, protectedApdu.Length - expectedLe.Length, expectedLe.Length);

            return protectedApdu;
        }


        /// <summary>
        /// ISO9797-1 Padding Method 2: append 0x80 then pad with zeros up to a multiple of blockSize.
        /// </summary>
        public byte[] PadIso9797Method2(byte[] data, int blockSize)
        {
            int padLen = blockSize - (data.Length % blockSize);
            byte[] padded = new byte[data.Length + padLen];
            Array.Copy(data, padded, data.Length);
            padded[data.Length] = 0x80;
            // (The remaining bytes are already 0)
            return padded;
        }

        /// <summary>
        /// AES-CBC encryption with no padding (data must be block-aligned).
        /// </summary>
        public byte[] AesCbcEncrypt(byte[] key, byte[] data, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }
        public byte[] Aes256CbcEncrypt(byte[] key, byte[] data, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None; // Padding is handled manually
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        // Kolla 128, se om ens behövs
        public byte[] ComputeAes256Cmac(byte[] key, byte[] message)
        {
            CMac cmac = new CMac(new AesEngine(), 128); // CMAC length set to 128 bits (16 bytes)
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(message, 0, message.Length);
            byte[] output = new byte[cmac.GetMacSize()];
            cmac.DoFinal(output, 0);
            return output;
        }

        /// <summary>
        /// AES-ECB encryption with no padding.
        /// </summary>
        public byte[] AesEcbEncrypt(byte[] key, byte[] data)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        /// <summary>
        /// Compute AES CMAC over a message using the given key.
        /// This implementation uses BouncyCastle.
        /// </summary>
        public byte[] ComputeAesCmac(byte[] key, byte[] message)
        {
            CMac cmac = new CMac(new AesEngine());
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(message, 0, message.Length);
            byte[] output = new byte[cmac.GetMacSize()];
            cmac.DoFinal(output, 0);
            return output;
        }

        /// <summary>
        /// Concatenate an arbitrary number of byte arrays.
        /// </summary>
        public byte[] Concat(params byte[][] arrays)
        {
            int totalLength = arrays.Where(a => a != null).Sum(a => a.Length);
            byte[] result = new byte[totalLength];
            int pos = 0;
            foreach (byte[] arr in arrays)
            {
                if (arr != null)
                {
                    Array.Copy(arr, 0, result, pos, arr.Length);
                    pos += arr.Length;
                }
            }
            return result;
        }

        public static byte[] ComputeSSC()
        {
            return new byte[8]; // ✅ Correct: SSC should be 8 bytes of zero
        }

        public async Task TestSecureSelectApdu(IsoDep isoDep, SecureMessaging secureMessaging)
        {
            try
            {
                Console.WriteLine("🔹 Starting Secure SELECT APDU Test...");

                // 🔹 Example: SELECT EF.COM (File ID 0x011E)
                byte[] selectApdu = new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E, 0x00 };
                Console.WriteLine($"🔹 Plain SELECT APDU: {BitConverter.ToString(selectApdu)}");

                // 🔹 Secure APDU Protection
                byte[] secureApdu = secureMessaging.ProtectCommand(selectApdu, null, null);
                Console.WriteLine($"🔹 Secure SELECT APDU (Encrypted): {BitConverter.ToString(secureApdu)}");

                // 🔹 Send Secure APDU
                byte[] responseApdu = await isoDep.TransceiveAsync(secureApdu);
                Console.WriteLine($"🔹 Received Encrypted Response (Raw APDU): {BitConverter.ToString(responseApdu)}");

                // 🔹 Process Secure Response
                byte[] decryptedResponse = secureMessaging.UnprotectResponse(responseApdu);
                Console.WriteLine($"🔹 Decrypted Response: {BitConverter.ToString(decryptedResponse)}");

                // Extract and log SW1, SW2
                int length = decryptedResponse.Length;
                if (length >= 2)
                {
                    byte sw1 = decryptedResponse[length - 2];
                    byte sw2 = decryptedResponse[length - 1];
                    Console.WriteLine($"🔹 Status Word (SW1 SW2): {sw1:X2} {sw2:X2}");

                    if (sw1 == 0x90 && sw2 == 0x00)
                    {
                        Console.WriteLine("✅ File selected successfully!");
                    }
                    else
                    {
                        Console.WriteLine("❌ File selection failed.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Secure SELECT APDU Test Failed: {ex.Message}");
            }
        }

        public async Task TestSecureApduExchange(IsoDep isoDep, SecureMessaging secureMessaging)
        {
            try
            {
                Console.WriteLine("🔹 Starting Secure APDU Exchange Test...");

                // Example APDU: Read first 8 bytes of DG1 (Document Data)
                byte[] readBinaryHeader = new byte[] { 0x00, 0xB0, 0x00, 0x00 }; // ReadBinary Command
                byte[] expectedResponseLength = new byte[] { 0x08 }; // Expect 8 bytes back

                // 🔹 Secure APDU Protection
                byte[] secureApdu = secureMessaging.ProtectCommand(readBinaryHeader, null, expectedResponseLength);
                Console.WriteLine($"🔹 Secure APDU (Encrypted): {BitConverter.ToString(secureApdu)}");

                // 🔹 Send Secure APDU
                byte[] responseApdu = await isoDep.TransceiveAsync(secureApdu);
                Console.WriteLine($"🔹 Received Encrypted Response (Raw APDU): {BitConverter.ToString(responseApdu)}"); // ✅ Log full response

                // 🔹 Process Secure Response
                byte[] decryptedResponse = secureMessaging.UnprotectResponse(responseApdu);
                Console.WriteLine($"🔹 Decrypted Response: {BitConverter.ToString(decryptedResponse)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Secure APDU Test Failed: {ex.Message}");
            }
        }

        public byte[] ExtractDO87(byte[] responseApdu)
        {
            Console.WriteLine("🔹 Extracting DO87 (Encrypted Data)...");

            int index = 0;
            int length = 0; // Declare length here

            while (index < responseApdu.Length)
            {
                byte tag = responseApdu[index++];

                if (tag == 0x87) // DO87 tag
                {
                    length = responseApdu[index++]; // Get length
                    if (responseApdu[index] == 0x01) // Indicator for encrypted data
                    {
                        index++;
                        byte[] encryptedData = new byte[length - 1]; // Exclude the indicator byte
                        Array.Copy(responseApdu, index, encryptedData, 0, encryptedData.Length);
                        Console.WriteLine($"✅ Extracted Encrypted Data: {BitConverter.ToString(encryptedData)}");
                        return encryptedData;
                    }
                }

                index += length; // ✅ Now length is always accessible
            }

            throw new Exception("❌ DO87 not found in response");
        }

        public byte[] ExtractDO8E(byte[] responseApdu)
        {
            Console.WriteLine("🔹 Extracting DO8E (MAC)...");

            int index = 0;
            int length = 0; // Declare length here

            while (index < responseApdu.Length)
            {
                byte tag = responseApdu[index++];

                if (tag == 0x8E) // DO8E tag
                {
                    length = responseApdu[index++]; // Get MAC length
                    byte[] mac = new byte[length];
                    Array.Copy(responseApdu, index, mac, 0, length);
                    Console.WriteLine($"✅ Extracted MAC: {BitConverter.ToString(mac)}");
                    return mac;
                }

                index += length; // ✅ Now length is always accessible
            }

            throw new Exception("❌ DO8E not found in response");
        }

        public byte[] UnprotectResponse(byte[] responseApdu)
        {
            Console.WriteLine("🔹 Unprotecting Secure Response...");
            Console.WriteLine($"🔹 Full Response APDU: {BitConverter.ToString(responseApdu)}");

            // 1. Check for Error (SW1 SW2)
            if (responseApdu.Length == 2 && responseApdu[0] == 0x67 && responseApdu[1] == 0x00)
            {
                Console.WriteLine("❌ Received `67 00` - Wrong Length. Secure Messaging might be incorrect.");
                return new byte[0];
            }

            // 2. Find the start of DO8E (MAC)
            int indexOfDo8e = Array.IndexOf(responseApdu, (byte)0x8E);
            if (indexOfDo8e < 0)
                throw new Exception("❌ DO8E not found in response");

            // 3. Extract DO8E (MAC)
            // The tag 0x8E is at indexOfDo8e, next byte is the length
            int macLen = responseApdu[indexOfDo8e + 1];
            byte[] receivedMAC = new byte[macLen];
            Array.Copy(responseApdu, indexOfDo8e + 2, receivedMAC, 0, macLen);
            Console.WriteLine($"✅ Extracted MAC: {BitConverter.ToString(receivedMAC)}");

            // 4. The MAC is computed over all response data preceding DO8E.
            byte[] responseDataForMac = responseApdu.Take(indexOfDo8e).ToArray();
            Console.WriteLine($"🔹 Response Data for MAC (DO87 and DO99): {BitConverter.ToString(responseDataForMac)}");

            // 5. Increment SSC for response processing
            IncrementSSC();
            Console.WriteLine($"🔹 SSC after incrementing: {BitConverter.ToString(ssc)}");

            // 6. Compute padded SSC (8 zero bytes concatenated with SSC)
            byte[] paddedSSC = Concat(new byte[8], ssc);
            Console.WriteLine($"🔹 Padded SSC: {BitConverter.ToString(paddedSSC)}");

            // 7. Concatenate paddedSSC with the response data (DO87 and DO99) and pad
            byte[] macInput = PadIso9797Method2(Concat(paddedSSC, responseDataForMac), blockSize);
            byte[] expectedMACFull = ComputeAes256Cmac(ksMac, macInput);
            byte[] expectedMAC = expectedMACFull.Take(8).ToArray(); // first 8 bytes
            Console.WriteLine($"🔹 Computed MAC: {BitConverter.ToString(expectedMAC)}");

            // 8. Validate MAC
            if (!expectedMAC.SequenceEqual(receivedMAC))
            {
                Console.WriteLine("❌ MAC Verification Failed - Data may be tampered!");
                throw new Exception("MAC Verification Failed");
            }
            Console.WriteLine("✅ MAC Verified Successfully!");

            // 9. Extract DO87 to decrypt the response data
            // For decryption, you need the encrypted data from DO87.
            // Assuming DO87 is the first TLV in responseDataForMac:
            if (responseDataForMac[0] != 0x87)
                throw new Exception("❌ Expected DO87 as first TLV in response");
            int do87Len = responseDataForMac[1];
            // Check that the first byte of DO87's value indicates encrypted data (0x01)
            if (responseDataForMac[2] != 0x01)
                throw new Exception("❌ DO87 does not indicate encrypted data");
            // The encrypted data is the remainder of DO87's value.
            byte[] encryptedData = new byte[do87Len - 1];
            Array.Copy(responseDataForMac, 3, encryptedData, 0, encryptedData.Length);
            Console.WriteLine($"✅ Extracted Encrypted Data: {BitConverter.ToString(encryptedData)}");

            // 10. Decrypt the encrypted data
            byte[] iv = AesEcbEncrypt(ksEnc, paddedSSC);
            Console.WriteLine($"🔹 Generated IV: {BitConverter.ToString(iv)}");
            byte[] decryptedData = Aes256CbcEncrypt(ksEnc, encryptedData, iv);
            Console.WriteLine($"🔹 Decrypted Response: {BitConverter.ToString(decryptedData)}");

            return decryptedData;
        }



        public void IncrementSSC()
        {
            if (ssc.Length != 8)
                throw new Exception("SSC must be 64-bit (8 bytes) for Secure Messaging");

            // Convert SSC to BigInteger (big-endian)
            Org.BouncyCastle.Math.BigInteger sscInt = new Org.BouncyCastle.Math.BigInteger(1, ssc);

            // Increment SSC
            sscInt = sscInt.Add(Org.BouncyCastle.Math.BigInteger.One);

            // Convert back to byte array (big-endian, exactly 8 bytes)
            byte[] newSSC = sscInt.ToByteArrayUnsigned();

            // Ensure exactly 8 bytes with zero-padding
            if (newSSC.Length < 8)
            {
                byte[] paddedSSC = new byte[8];
                Array.Copy(newSSC, 0, paddedSSC, 8 - newSSC.Length, newSSC.Length);
                ssc = paddedSSC;
            }
            else if (newSSC.Length > 8)
            {
                ssc = newSSC.Take(8).ToArray(); // Trim if longer
            }
            else
            {
                ssc = newSSC;
            }

            Console.WriteLine($"🔹 Incremented SSC: {BitConverter.ToString(ssc)}");
        }

        public bool VerifyResponseMAC(byte[] responseApdu)
        {
            Console.WriteLine("🔹 Verifying Response MAC...");

            if (responseApdu == null || responseApdu.Length < 10)
            {
                Console.WriteLine("❌ Response APDU is too short to contain valid MAC.");
                return false;
            }

            // 🔹 Step 1: Find DO8E (MAC tag) in the response
            int indexOfDo8e = Array.IndexOf(responseApdu, (byte)0x8E);
            if (indexOfDo8e < 0)
            {
                Console.WriteLine("❌ DO8E (MAC) not found in response.");
                return false;
            }

            // 🔹 Step 2: Extract MAC from response (DO8E tag is followed by length byte)
            int macLength = responseApdu[indexOfDo8e + 1];
            byte[] receivedMAC = responseApdu.Skip(indexOfDo8e + 2).Take(macLength).ToArray();
            Console.WriteLine($"✅ Extracted MAC: {BitConverter.ToString(receivedMAC)}");

            // 🔹 Step 3: Extract DO99 (Status Word)
            int indexOfDo99 = Array.IndexOf(responseApdu, (byte)0x99);
            if (indexOfDo99 < 0 || indexOfDo99 + 2 >= responseApdu.Length)
            {
                Console.WriteLine("❌ DO99 (Status Word) not found.");
                return false;
            }

            byte[] do99 = responseApdu.Skip(indexOfDo99).Take(4).ToArray();
            Console.WriteLine($"✅ Extracted DO99 (Status Word): {BitConverter.ToString(do99)}");

            // 🔹 Step 4: Prepare input for MAC verification
            IncrementSSC();  // SSC must be incremented for response verification
            byte[] paddedSSC = Concat(new byte[8], ssc);
            byte[] macInput = PadIso9797Method2(Concat(paddedSSC, do99), blockSize);

            // 🔹 Step 5: Compute the expected MAC
            byte[] expectedMACFull = ComputeAes256Cmac(ksMac, macInput);
            byte[] expectedMAC = expectedMACFull.Take(8).ToArray();
            Console.WriteLine($"🔹 Computed Expected MAC: {BitConverter.ToString(expectedMAC)}");

            // 🔹 Step 6: Compare computed MAC with received MAC
            if (!expectedMAC.SequenceEqual(receivedMAC))
            {
                Console.WriteLine("❌ MAC Verification Failed - Data may be tampered with!");
                return false;
            }

            Console.WriteLine("✅ MAC Verification Successful!");
            return true;
        }


    }
}
