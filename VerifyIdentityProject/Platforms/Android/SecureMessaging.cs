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
using VerifyIdentityProject.Platforms.Android;

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

            Console.WriteLine($"🔹 SecureMessaging initialized with:");
            Console.WriteLine($"   KSEnc: {BitConverter.ToString(ksEnc)}");
            Console.WriteLine($"   KSMAC: {BitConverter.ToString(ksMac)}");
            Console.WriteLine($"   SSC: {BitConverter.ToString(ssc)}");
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
            Console.WriteLine("🔹 ProtectCommand: Start");

            // 1. Increment SSC
            IncrementSSC();
            Console.WriteLine($"🔹 Incremented SSC: {BitConverter.ToString(ssc)}");

            // 2. Mask the header (set CLA to 0x0C) and pad it.
            byte[] maskedHeader = MaskCommandHeader(apduHeader);
            Console.WriteLine($"🔹 Masked APDU Header: {BitConverter.ToString(maskedHeader)}");

            // 3. If there is a command data field, build DO87.
            byte[] do87 = (apduData != null && apduData.Length > 0) ? BuildDO87(apduData) : null;
            if (do87 != null)
                Console.WriteLine($"🔹 Built DO87 (Encrypted Data Field): {BitConverter.ToString(do87)}");

            // 4. If an expected response length is provided, build DO97.
            byte[] do97 = (le != null && le.Length > 0) ? BuildDO97(le) : null;
            if (do97 != null)
                Console.WriteLine($"🔹 Built DO97 (Expected Response Length): {BitConverter.ToString(do97)}");

            // 5. Concatenate M = maskedHeader || do87 || do97.
            byte[] M = Concat(maskedHeader, do87, do97);
            Console.WriteLine($"🔹 Concatenated M (Header + DO87 + DO97): {BitConverter.ToString(M)}");

            // 6. Compute padded SSC (8 zero bytes concatenated with SSC)
            byte[] paddedSSC = Concat(new byte[8], ssc);
            Console.WriteLine($"🔹 Padded SSC: {BitConverter.ToString(paddedSSC)}");

            // 7. Compute N = Pad( paddedSSC || M ) using ISO9797-1 Padding Method 2.
            byte[] N = PadIso9797Method2(Concat(paddedSSC, M), blockSize);
            Console.WriteLine($"🔹 Padded N (Padded SSC + M): {BitConverter.ToString(N)}");

            // 8. Compute MAC (using AES-CMAC) over N.
            byte[] mac = ComputeAesCmac(ksMac, N);
            if (mac.Length > 8)
                mac = mac.Take(8).ToArray();
            Console.WriteLine($"🔹 Computed MAC (DO8E): {BitConverter.ToString(mac)}");

            // 9. Build DO8E from the MAC.
            byte[] do8e = BuildDO8E(mac);
            Console.WriteLine($"🔹 Built DO8E (MAC Structure): {BitConverter.ToString(do8e)}");

            // 10. Construct final protected APDU
            byte[] finalApdu = ConstructProtectedAPDU(maskedHeader.Take(4).ToArray(), do87, do97, do8e, new byte[] { 0x00 });
            Console.WriteLine($"🔹 Final Protected APDU: {BitConverter.ToString(finalApdu)}");

            Console.WriteLine("✅ ProtectCommand: End");
            return finalApdu;
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

            Console.WriteLine("🔹 MaskCommandHeader: Start");

            // Log the original APDU header
            Console.WriteLine($"🔹 Original APDU Header: {BitConverter.ToString(header)}");

            // Create the masked header and apply modifications
            byte[] masked = new byte[4];
            masked[0] = 0x0C; // Mask CLA to 0x0C
            Array.Copy(header, 1, masked, 1, 3);

            Console.WriteLine($"🔹 Masked APDU Header (CLA set to 0x0C): {BitConverter.ToString(masked)}");

            // Pad the masked header using ISO9797-1 Method 2 padding
            byte[] paddedHeader = PadIso9797Method2(masked, blockSize);

            Console.WriteLine($"🔹 Padded APDU Header (ISO9797-1 Padding): {BitConverter.ToString(paddedHeader)}");

            Console.WriteLine("✅ MaskCommandHeader: End");

            return paddedHeader;
        }

        /// <summary>
        /// Build DO87: Tag 0x87, length, 0x01 (indicator for encrypted data) and then the encrypted (and padded) data.
        /// </summary>
        public byte[] BuildDO87(byte[] data)
        {
            Console.WriteLine("🔹 BuildDO87: Start");

            // Log input data before encryption
            Console.WriteLine($"🔹 Original Data (Plaintext): {BitConverter.ToString(data)}");

            // 1. Compute padded SSC (8 zero bytes + SSC)
            byte[] paddedSSC = Concat(new byte[8], ssc);
            Console.WriteLine($"🔹 Padded SSC: {BitConverter.ToString(paddedSSC)}");

            // 2. Compute IV = AES-ECB(ksEnc, paddedSSC)
            byte[] iv = AesEcbEncrypt(ksEnc, paddedSSC);
            Console.WriteLine($"🔹 Computed IV (AES-ECB Enc of Padded SSC): {BitConverter.ToString(iv)}");

            // 3. Pad the data using ISO9797-1 Method 2 padding
            byte[] paddedData = PadIso9797Method2(data, blockSize);
            Console.WriteLine($"🔹 Padded Data (ISO9797-1 Padding): {BitConverter.ToString(paddedData)}");

            // 4. Encrypt using AES-CBC with computed IV
            byte[] encryptedData = AesCbcEncrypt(ksEnc, paddedData, iv);
            Console.WriteLine($"🔹 Encrypted Data (AES-CBC Enc): {BitConverter.ToString(encryptedData)}");

            // 5. Build DO87: Tag (0x87), length, 0x01 (indicates encrypted data), then encryptedData
            byte[] do87 = new byte[3 + encryptedData.Length];
            do87[0] = 0x87;
            do87[1] = (byte)(1 + encryptedData.Length); // length field
            do87[2] = 0x01; // Indicator for encrypted data
            Array.Copy(encryptedData, 0, do87, 3, encryptedData.Length);

            Console.WriteLine($"🔹 Final DO87 (Encrypted TLV): {BitConverter.ToString(do87)}");
            Console.WriteLine("✅ BuildDO87: End");

            return do87;
        }


        /// <summary>
        /// Build DO97: Tag 0x97, length of Le field, and then Le.
        /// </summary>
        public byte[] BuildDO97(byte[] le)
        {
            Console.WriteLine("🔹 BuildDO97: Start");

            // Log input length (Le)
            Console.WriteLine($"🔹 Input Expected Length (Le): {BitConverter.ToString(le)}");

            // 1. Allocate space for DO97: Tag (0x97), length of Le, then Le itself
            byte[] do97 = new byte[2 + le.Length];

            // 2. Set the tag and length
            do97[0] = 0x97;
            do97[1] = (byte)le.Length;

            // 3. Copy Le value into DO97
            Array.Copy(le, 0, do97, 2, le.Length);

            // Log final DO97 structure
            Console.WriteLine($"🔹 Final DO97 (Le TLV Structure): {BitConverter.ToString(do97)}");

            Console.WriteLine("✅ BuildDO97: End");

            return do97;
        }


        /// <summary>
        /// Build DO8E: Tag 0x8E, length (should be 8), and then the MAC.
        /// </summary>
        public byte[] BuildDO8E(byte[] mac)
        {
            Console.WriteLine("🔹 BuildDO8E: Start");

            // Log input MAC
            Console.WriteLine($"🔹 Input MAC: {BitConverter.ToString(mac)}");

            // 1. Allocate space for DO8E: Tag (0x8E), length of MAC, then MAC itself
            byte[] do8e = new byte[2 + mac.Length];

            // 2. Set the tag and length
            do8e[0] = 0x8E;
            do8e[1] = (byte)mac.Length;

            // 3. Copy MAC value into DO8E
            Array.Copy(mac, 0, do8e, 2, mac.Length);

            // Log final DO8E structure
            Console.WriteLine($"🔹 Final DO8E (MAC TLV Structure): {BitConverter.ToString(do8e)}");

            Console.WriteLine("✅ BuildDO8E: End");

            return do8e;
        }


        /// <summary>
        /// Construct the final protected APDU.
        /// Here we assume that the final APDU is:
        ///   [Original header’s 4 bytes] || Lc || (DO87 || DO97 || DO8E) || Le (set to 0x00)
        /// </summary>
        public byte[] ConstructProtectedAPDU(byte[] header4, byte[] do87, byte[] do97, byte[] do8e, byte[] expectedLe)
        {
            Console.WriteLine("🔹 ConstructProtectedAPDU: Start");

            // Log input header (first 4 bytes)
            Console.WriteLine($"🔹 APDU Header (CLA, INS, P1, P2): {BitConverter.ToString(header4)}");

            // Log each data object being concatenated
            if (do87 != null)
                Console.WriteLine($"🔹 DO87 (Encrypted Data): {BitConverter.ToString(do87)}");
            if (do97 != null)
                Console.WriteLine($"🔹 DO97 (Expected Response Length): {BitConverter.ToString(do97)}");
            if (do8e != null)
                Console.WriteLine($"🔹 DO8E (MAC): {BitConverter.ToString(do8e)}");

            // 1. Concatenate the data fields: DO87 || DO97 || DO8E
            byte[] dataField = Concat(do87, do97, do8e);
            Console.WriteLine($"🔹 Concatenated Data Field (DO87 || DO97 || DO8E): {BitConverter.ToString(dataField)}");

            // 2. Compute Lc (length of data field)
            byte lc = (byte)dataField.Length;
            Console.WriteLine($"🔹 Lc (Length of Data Field): {lc}");

            // 3. Allocate space for final APDU: Header (4 bytes) + Lc + Data + Le
            byte[] protectedApdu = new byte[header4.Length + 1 + dataField.Length + expectedLe.Length];

            // 4. Copy header into protected APDU
            Array.Copy(header4, 0, protectedApdu, 0, header4.Length);

            // 5. Insert Lc
            protectedApdu[header4.Length] = lc;

            // 6. Insert Data Field (DO87 || DO97 || DO8E)
            Array.Copy(dataField, 0, protectedApdu, header4.Length + 1, dataField.Length);

            // 7. Set expected response length (Le)
            Array.Copy(expectedLe, 0, protectedApdu, protectedApdu.Length - expectedLe.Length, expectedLe.Length);
            Console.WriteLine($"🔹 Expected Response Length (Le): {BitConverter.ToString(expectedLe)}");

            // Log final protected APDU
            Console.WriteLine($"✅ Final Protected APDU: {BitConverter.ToString(protectedApdu)}");

            Console.WriteLine("✅ ConstructProtectedAPDU: End");

            return protectedApdu;
        }


        /// <summary>
        /// ISO9797-1 Padding Method 2: append 0x80 then pad with zeros up to a multiple of blockSize.
        /// </summary>
        public byte[] PadIso9797Method2(byte[] data, int blockSize)
        {
            Console.WriteLine("🔹 PadIso9797Method2: Start");

            // 1. Calculate padding length
            int padLen = blockSize - (data.Length % blockSize);
            Console.WriteLine($"🔹 Original Data Length: {data.Length}");
            Console.WriteLine($"🔹 Block Size: {blockSize}");
            Console.WriteLine($"🔹 Padding Length Needed: {padLen}");

            // 2. Create new padded byte array
            byte[] padded = new byte[data.Length + padLen];

            // 3. Copy original data into padded array
            Array.Copy(data, padded, data.Length);

            // 4. Apply padding rule: Append 0x80 followed by zeroes
            padded[data.Length] = 0x80;
            Console.WriteLine($"🔹 Padding Applied: 0x80 at index {data.Length}");

            // 5. Log final padded data
            Console.WriteLine($"✅ Padded Data (ISO 9797-1 Method 2): {BitConverter.ToString(padded)}");
            Console.WriteLine("✅ PadIso9797Method2: End");

            return padded;
        }


        /// <summary>
        /// AES-CBC encryption with no padding (data must be block-aligned).
        /// </summary>
        public byte[] AesCbcEncrypt(byte[] key, byte[] data, byte[] iv)
        {
            Console.WriteLine("🔹 AesCbcEncrypt: Start");

            // 1. Log Key, IV, and Data
            Console.WriteLine($"🔹 AES Key: {BitConverter.ToString(key)}");
            Console.WriteLine($"🔹 IV: {BitConverter.ToString(iv)}");
            Console.WriteLine($"🔹 Data to Encrypt: {BitConverter.ToString(data)}");
            Console.WriteLine($"🔹 Data Length: {data.Length} bytes");

            if (data.Length % 16 != 0)
            {
                Console.WriteLine("❌ ERROR: Data length is not a multiple of 16! AES-CBC requires block-aligned data.");
                throw new ArgumentException("Data length must be a multiple of the AES block size (16 bytes).");
            }

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None; // No padding, data must be aligned

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);

                    // 2. Log Encrypted Data
                    Console.WriteLine($"✅ Encrypted Data: {BitConverter.ToString(encryptedData)}");
                    Console.WriteLine("✅ AesCbcEncrypt: End");

                    return encryptedData;
                }
            }
        }

        /// <summary>
        /// Encrypts data using AES-256 in CBC mode.
        /// - Requires a 32-byte key (AES-256).
        /// - Requires a 16-byte IV.
        /// - Data must be a multiple of 16 bytes (handled before calling this function).
        /// - Returns the encrypted ciphertext.
        /// </summary>
        public byte[] Aes256CbcEncrypt(byte[] key, byte[] data, byte[] iv)
        {
            Console.WriteLine("🔹 Aes256CbcEncrypt: Start");

            // 1. Validate Key Length (Must be 32 bytes for AES-256)
            if (key.Length != 32)
            {
                Console.WriteLine("❌ ERROR: Key length is invalid! AES-256 requires a 32-byte key.");
                throw new ArgumentException("Invalid key length. AES-256 requires a 32-byte key.");
            }

            // 2. Validate IV Length (Must be 16 bytes)
            if (iv.Length != 16)
            {
                Console.WriteLine("❌ ERROR: IV length is invalid! AES-CBC requires a 16-byte IV.");
                throw new ArgumentException("Invalid IV length. AES-CBC requires a 16-byte IV.");
            }

            // 3. Validate Data Length (Must be block-aligned to 16 bytes)
            if (data.Length % 16 != 0)
            {
                Console.WriteLine("❌ ERROR: Data length is not a multiple of 16! AES-CBC requires block-aligned data.");
                throw new ArgumentException("Data length must be a multiple of the AES block size (16 bytes).");
            }

            // 4. Log Inputs
            Console.WriteLine($"🔹 AES-256 Key: {BitConverter.ToString(key)}");
            Console.WriteLine($"🔹 IV: {BitConverter.ToString(iv)}");
            Console.WriteLine($"🔹 Data to Encrypt: {BitConverter.ToString(data)}");
            Console.WriteLine($"🔹 Data Length: {data.Length} bytes");

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None; // No padding, ensure data is block-aligned

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);

                    // 5. Log Encrypted Data
                    Console.WriteLine($"✅ Encrypted Data: {BitConverter.ToString(encryptedData)}");
                    Console.WriteLine("✅ Aes256CbcEncrypt: End");

                    return encryptedData;
                }
            }
        }

        /// <summary>
        /// Computes an AES-256 CMAC (Cipher-based Message Authentication Code).
        /// - Requires a 32-byte key (AES-256).
        /// - Computes a 16-byte CMAC over the input message.
        /// - Used for message integrity verification in secure messaging.
        /// - Returns the CMAC authentication tag.
        /// </summary>
        public byte[] ComputeAes256Cmac(byte[] key, byte[] message)
        {
            Console.WriteLine("🔹 ComputeAes256Cmac: Start");

            // 1. Validate Key Length (Must be 32 bytes for AES-256 CMAC)
            if (key.Length != 32)
            {
                Console.WriteLine("❌ ERROR: Key length is invalid! AES-256 CMAC requires a 32-byte key.");
                throw new ArgumentException("Invalid key length. AES-256 CMAC requires a 32-byte key.");
            }

            // 2. Validate Message Length
            if (message == null || message.Length == 0)
            {
                Console.WriteLine("❌ ERROR: Message is empty! Cannot compute CMAC.");
                throw new ArgumentException("Message cannot be null or empty.");
            }

            // 3. Log Inputs
            Console.WriteLine($"🔹 AES-256 CMAC Key: {BitConverter.ToString(key)}");
            Console.WriteLine($"🔹 Message Length: {message.Length} bytes");
            Console.WriteLine($"🔹 Message Data: {BitConverter.ToString(message)}");

            // 4. Compute CMAC
            CMac cmac = new CMac(new AesEngine(), 128); // CMAC output size = 128 bits (16 bytes)
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(message, 0, message.Length);
            byte[] cmacOutput = new byte[cmac.GetMacSize()];
            cmac.DoFinal(cmacOutput, 0);

            // 5. Log CMAC Output
            Console.WriteLine($"✅ Computed CMAC: {BitConverter.ToString(cmacOutput)}");
            Console.WriteLine("✅ ComputeAes256Cmac: End");

            return cmacOutput;
        }

        /// <summary>
        /// Performs AES-ECB (Electronic Codebook) encryption with no padding.
        /// - Uses the provided key for encryption.
        /// - AES-ECB encrypts blocks independently (not recommended for large data due to lack of diffusion).
        /// - The input data must be a multiple of 16 bytes (AES block size).
        /// - Returns the encrypted data.
        /// </summary>
        public byte[] AesEcbEncrypt(byte[] key, byte[] data)
        {
            Console.WriteLine("🔹 AesEcbEncrypt: Start");

            // 1. Validate Key Length (Must be 16, 24, or 32 bytes for AES)
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                Console.WriteLine("❌ ERROR: Key length is invalid! Must be 16, 24, or 32 bytes for AES.");
                throw new ArgumentException("Invalid AES key length. Must be 16, 24, or 32 bytes.");
            }

            // 2. Validate Data Length (Must be a multiple of 16 for ECB mode)
            if (data.Length % 16 != 0)
            {
                Console.WriteLine("❌ ERROR: Data length is not a multiple of 16! AES requires block-aligned data.");
                throw new ArgumentException("Invalid data length. AES-ECB requires input to be a multiple of 16 bytes.");
            }

            // 3. Log Inputs
            Console.WriteLine($"🔹 AES Key: {BitConverter.ToString(key)}");
            Console.WriteLine($"🔹 Data Length: {data.Length} bytes");
            Console.WriteLine($"🔹 Input Data: {BitConverter.ToString(data)}");

            // 4. Perform AES-ECB Encryption
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;

                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                {
                    byte[] encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);

                    // 5. Log Output
                    Console.WriteLine($"✅ Encrypted Data: {BitConverter.ToString(encryptedData)}");
                    Console.WriteLine("✅ AesEcbEncrypt: End");

                    return encryptedData;
                }
            }
        }

        /// <summary>
        /// Computes AES-CMAC (Cipher-based Message Authentication Code) over a given message using the specified key.
        /// - Uses the AES cipher in CMAC mode (Cipher-based MAC).
        /// - Ensures message integrity and authenticity.
        /// - Uses BouncyCastle's `CMac` implementation.
        /// - Returns a 16-byte CMAC hash.
        /// </summary>
        public byte[] ComputeAesCmac(byte[] key, byte[] message)
        {
            Console.WriteLine("🔹 ComputeAesCmac: Start");

            // 1. Validate Key Length (AES Key must be 16, 24, or 32 bytes)
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
            {
                Console.WriteLine("❌ ERROR: Invalid AES key length! Must be 16, 24, or 32 bytes.");
                throw new ArgumentException("Invalid AES key length. Must be 16, 24, or 32 bytes.");
            }

            // 2. Validate Message Length
            if (message == null || message.Length == 0)
            {
                Console.WriteLine("❌ ERROR: Message cannot be null or empty.");
                throw new ArgumentException("Message cannot be null or empty.");
            }

            // 3. Log Inputs
            Console.WriteLine($"🔹 AES Key: {BitConverter.ToString(key)}");
            Console.WriteLine($"🔹 Message Length: {message.Length} bytes");
            Console.WriteLine($"🔹 Message Data: {BitConverter.ToString(message)}");

            // 4. Compute AES-CMAC
            CMac cmac = new CMac(new AesEngine()); // AES CMAC instance
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(message, 0, message.Length);
            byte[] output = new byte[cmac.GetMacSize()];
            cmac.DoFinal(output, 0);

            // 5. Log Output
            Console.WriteLine($"✅ Computed CMAC: {BitConverter.ToString(output)}");
            Console.WriteLine("✅ ComputeAesCmac: End");

            return output;
        }

        /// <summary>
        /// Concatenates multiple byte arrays into a single byte array.
        /// - **Handles null arrays gracefully** (skips them).
        /// - **Efficiently precomputes total length** before allocation.
        /// - **Used in Secure Messaging for constructing APDUs**.
        /// - **Logs input arrays and the final concatenated output**.
        /// </summary>
        public byte[] Concat(params byte[][] arrays)
        {
            Console.WriteLine("🔹 Concat: Start");

            // 1. Validate input (ensure at least one array is non-null)
            if (arrays == null || arrays.Length == 0 || arrays.All(a => a == null))
            {
                Console.WriteLine("❌ ERROR: No valid arrays provided for concatenation.");
                throw new ArgumentException("At least one non-null byte array is required.");
            }

            // 2. Compute total length (skips null arrays)
            int totalLength = arrays.Where(a => a != null).Sum(a => a.Length);
            Console.WriteLine($"🔹 Total Concatenated Length: {totalLength} bytes");

            // 3. Allocate final result array
            byte[] result = new byte[totalLength];
            int pos = 0;

            // 4. Concatenate arrays
            foreach (byte[] arr in arrays)
            {
                if (arr != null)
                {
                    Console.WriteLine($"🔹 Adding Array: {BitConverter.ToString(arr)}");
                    Array.Copy(arr, 0, result, pos, arr.Length);
                    pos += arr.Length;
                }
            }

            // 5. Log final result
            Console.WriteLine($"✅ Concatenated Output: {BitConverter.ToString(result)}");
            Console.WriteLine("✅ Concat: End");

            return result;
        }

        /// <summary>
        /// Computes the initial Send Sequence Counter (SSC) for Secure Messaging.
        /// - **Always returns an 8-byte array filled with zeros (0000000000000000).**
        /// - **Used in Secure Messaging (PACE/BAC) for encryption and authentication.**
        /// - **Ensures SSC starts at zero before incrementing with each APDU exchange.**
        /// - **Logs SSC initialization for debugging.**
        /// </summary>
        public static byte[] ComputeSSC()
        {
            byte[] ssc = new byte[8]; // ✅ SSC starts at 0000000000000000

            Console.WriteLine($"✅ SSC Initialized: {BitConverter.ToString(ssc)}");

            return ssc;
        }


        /// <summary>
        /// Extracts the encrypted data from DO87 (Response APDU).
        /// - **DO87 is a TLV structure used in Secure Messaging for encrypted data.**
        /// - **Finds the tag (0x87), extracts the encrypted data, and logs it.**
        /// - **Ensures proper parsing before decryption to avoid incorrect extractions.**
        /// - **Throws an exception if DO87 is missing in the response.**
        /// </summary>
        /// <param name="responseApdu">The full APDU response received from the chip.</param>
        /// <returns>The extracted encrypted data from DO87.</returns>
        /// <exception cref="Exception">Thrown if DO87 is not found in the response.</exception>
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
                    if (index >= responseApdu.Length)
                        throw new Exception("❌ DO87 length byte missing!");

                    length = responseApdu[index++]; // Get length

                    if (index >= responseApdu.Length || length == 0)
                        throw new Exception("❌ Invalid DO87 length or missing data!");

                    if (responseApdu[index] == 0x01) // Indicator for encrypted data
                    {
                        index++; // Move past the indicator byte

                        if (index + (length - 1) > responseApdu.Length)
                            throw new Exception("❌ Encrypted data length exceeds response size!");

                        byte[] encryptedData = new byte[length - 1]; // Exclude the indicator byte
                        Array.Copy(responseApdu, index, encryptedData, 0, encryptedData.Length);

                        Console.WriteLine($"✅ Extracted Encrypted Data: {BitConverter.ToString(encryptedData)}");
                        return encryptedData;
                    }
                }

                // Ensure we don't skip beyond valid length
                if (length > 0 && index + length <= responseApdu.Length)
                    index += length;
                else
                    break;
            }

            throw new Exception("❌ DO87 not found in response");
        }

        /// <summary>
        /// Extracts the MAC (Message Authentication Code) from DO8E in the response APDU.
        /// - **DO8E is used in Secure Messaging for integrity verification.**
        /// - **Finds the tag (0x8E), extracts the MAC, and logs it.**
        /// - **Ensures the extracted MAC is properly formatted before verification.**
        /// - **Throws an exception if DO8E is missing in the response.**
        /// </summary>
        /// <param name="responseApdu">The full APDU response received from the chip.</param>
        /// <returns>The extracted MAC from DO8E.</returns>
        /// <exception cref="Exception">Thrown if DO8E is not found in the response.</exception>
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
                    if (index >= responseApdu.Length)
                        throw new Exception("❌ DO8E length byte missing!");

                    length = responseApdu[index++]; // Get MAC length

                    if (index + length > responseApdu.Length || length <= 0)
                        throw new Exception("❌ Invalid DO8E length or missing MAC!");

                    byte[] mac = new byte[length];
                    Array.Copy(responseApdu, index, mac, 0, length);

                    Console.WriteLine($"✅ Extracted MAC: {BitConverter.ToString(mac)}");
                    return mac;
                }

                // Ensure we don't skip beyond valid length
                if (length > 0 && index + length <= responseApdu.Length)
                    index += length;
                else
                    break;
            }

            throw new Exception("❌ DO8E not found in response");
        }

        /// <summary>
        /// Decrypts and verifies a Secure Messaging APDU response.
        /// - **Extracts the MAC (DO8E) and the encrypted response data (DO87).**
        /// - **Validates integrity using AES-CMAC (Compare received MAC with expected MAC).**
        /// - **Decrypts the response using AES-256-CBC.**
        /// - **Logs all critical steps for debugging and analysis.**
        /// </summary>
        /// <param name="responseApdu">The encrypted APDU response.</param>
        /// <returns>The decrypted response data.</returns>
        /// <exception cref="Exception">Thrown if the MAC verification fails or response is incorrectly formatted.</exception>
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
                throw new Exception("❌ DO8E (MAC) not found in response");

            // 3. Extract DO8E (MAC)
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

            // 7. Compute MAC over SSC || responseData (DO87 + DO99)
            byte[] macInput = PadIso9797Method2(Concat(paddedSSC, responseDataForMac), blockSize);
            byte[] expectedMACFull = ComputeAes256Cmac(ksMac, macInput);
            byte[] expectedMAC = expectedMACFull.Take(8).ToArray(); // Use first 8 bytes for verification
            Console.WriteLine($"🔹 Computed MAC: {BitConverter.ToString(expectedMAC)}");

            // 8. Validate MAC
            if (!expectedMAC.SequenceEqual(receivedMAC))
            {
                Console.WriteLine("❌ MAC Verification Failed - Data may be tampered!");
                throw new Exception("MAC Verification Failed");
            }
            Console.WriteLine("✅ MAC Verified Successfully!");

            // 9. Extract DO87 to decrypt the response data
            if (responseDataForMac[0] != 0x87)
                throw new Exception("❌ Expected DO87 as first TLV in response");

            int do87Len = responseDataForMac[1];
            if (do87Len < 2 || responseDataForMac.Length < do87Len + 2)
                throw new Exception("❌ DO87 length is invalid or insufficient data");

            // Check first byte of DO87's value (should be 0x01 for encrypted data)
            if (responseDataForMac[2] != 0x01)
                throw new Exception("❌ DO87 does not indicate encrypted data");

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

        /// <summary>
        /// Increments the Secure Messaging Send Sequence Counter (SSC).
        /// - **Ensures SSC is always 8 bytes (64-bit).**
        /// - **Uses BigInteger to prevent overflow errors.**
        /// - **Pads with leading zeros if the incremented value is shorter.**
        /// - **Logs the before-and-after SSC values for debugging.**
        /// </summary>
        public void IncrementSSC()
        {
            Console.WriteLine($"🔹 Current SSC before increment: {BitConverter.ToString(ssc)}");

            // Ensure SSC is 8 bytes long
            if (ssc.Length != 8)
                throw new Exception("SSC must be 64-bit (8 bytes) for Secure Messaging");

            // Convert SSC to BigInteger (big-endian)
            Org.BouncyCastle.Math.BigInteger sscInt = new Org.BouncyCastle.Math.BigInteger(1, ssc);

            // Increment SSC
            sscInt = sscInt.Add(Org.BouncyCastle.Math.BigInteger.One);

            // Convert back to byte array (big-endian, exactly 8 bytes)
            byte[] newSSC = sscInt.ToByteArrayUnsigned();

            // Ensure the new SSC is exactly 8 bytes long
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

            Console.WriteLine($"✅ Incremented SSC: {BitConverter.ToString(ssc)}");
        }


        /// <summary>
        /// Verifies the Message Authentication Code (MAC) in a secure response.
        /// - **Extracts and verifies DO8E (MAC) and DO99 (Status Word).**
        /// - **Ensures message integrity using AES-CMAC verification.**
        /// - **Prevents replay and tampering attacks.**
        /// - **Logs each step for debugging.**
        /// </summary>
        /// <param name="responseApdu">The APDU response to verify.</param>
        /// <returns>True if MAC verification is successful; otherwise, false.</returns>
        public bool VerifyResponseMAC(byte[] responseApdu)
        {
            Console.WriteLine("🔹 Verifying Response MAC...");

            // 1️⃣ Check if response is too short to contain a valid MAC
            if (responseApdu == null || responseApdu.Length < 10)
            {
                Console.WriteLine("❌ Response APDU is too short to contain a valid MAC.");
                return false;
            }

            // 2️⃣ Locate DO8E (MAC) tag in the response
            int indexOfDo8e = Array.IndexOf(responseApdu, (byte)0x8E);
            if (indexOfDo8e < 0)
            {
                Console.WriteLine("❌ DO8E (MAC) not found in response.");
                return false;
            }

            // 3️⃣ Extract MAC from DO8E
            int macLength = responseApdu[indexOfDo8e + 1];
            byte[] receivedMAC = responseApdu.Skip(indexOfDo8e + 2).Take(macLength).ToArray();
            Console.WriteLine($"✅ Extracted MAC: {BitConverter.ToString(receivedMAC)}");

            // 4️⃣ Locate DO99 (Status Word) in the response
            int indexOfDo99 = Array.IndexOf(responseApdu, (byte)0x99);
            if (indexOfDo99 < 0 || indexOfDo99 + 2 >= responseApdu.Length)
            {
                Console.WriteLine("❌ DO99 (Status Word) not found.");
                return false;
            }

            // 5️⃣ Extract DO99 (Status Word)
            byte[] do99 = responseApdu.Skip(indexOfDo99).Take(4).ToArray();
            Console.WriteLine($"✅ Extracted DO99 (Status Word): {BitConverter.ToString(do99)}");

            // 6️⃣ Prepare input for MAC verification
            Console.WriteLine("🔹 Preparing MAC input...");
            IncrementSSC();  // SSC must be incremented before verifying the MAC
            byte[] paddedSSC = Concat(new byte[8], ssc);
            byte[] macInput = PadIso9797Method2(Concat(paddedSSC, do99), blockSize);
            Console.WriteLine($"🔹 MAC Input: {BitConverter.ToString(macInput)}");

            // 7️⃣ Compute the expected MAC using AES-CMAC
            byte[] expectedMACFull = ComputeAes256Cmac(ksMac, macInput);
            byte[] expectedMAC = expectedMACFull.Take(8).ToArray(); // Only first 8 bytes are used
            Console.WriteLine($"🔹 Computed Expected MAC: {BitConverter.ToString(expectedMAC)}");

            // 8️⃣ Compare received MAC with expected MAC
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


// ---------- Tester methods------------

//public async Task TestSecureSelectApdu(IsoDep isoDep, SecureMessaging secureMessaging)
//{
//    try
//    {
//        Console.WriteLine("🔹 Starting Secure SELECT APDU Test...");

//        // 🔹 Example: SELECT EF.COM (File ID 0x011E)
//        byte[] selectApdu = new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E, 0x00 };
//        Console.WriteLine($"🔹 Plain SELECT APDU: {BitConverter.ToString(selectApdu)}");

//        // 🔹 Secure APDU Protection
//        byte[] secureApdu = secureMessaging.ProtectCommand(selectApdu, null, null);
//        Console.WriteLine($"🔹 Secure SELECT APDU (Encrypted): {BitConverter.ToString(secureApdu)}");

//        // 🔹 Send Secure APDU
//        byte[] responseApdu = await isoDep.TransceiveAsync(secureApdu);
//        Console.WriteLine($"🔹 Received Encrypted Response (Raw APDU): {BitConverter.ToString(responseApdu)}");

//        // 🔹 Process Secure Response
//        byte[] decryptedResponse = secureMessaging.UnprotectResponse(responseApdu);
//        Console.WriteLine($"🔹 Decrypted Response: {BitConverter.ToString(decryptedResponse)}");

//        // Extract and log SW1, SW2
//        int length = decryptedResponse.Length;
//        if (length >= 2)
//        {
//            byte sw1 = decryptedResponse[length - 2];
//            byte sw2 = decryptedResponse[length - 1];
//            Console.WriteLine($"🔹 Status Word (SW1 SW2): {sw1:X2} {sw2:X2}");

//            if (sw1 == 0x90 && sw2 == 0x00)
//            {
//                Console.WriteLine("✅ File selected successfully!");
//            }
//            else
//            {
//                Console.WriteLine("❌ File selection failed.");
//            }
//        }
//    }
//    catch (Exception ex)
//    {
//        Console.WriteLine($"❌ Secure SELECT APDU Test Failed: {ex.Message}");
//    }
//}

//public async Task TestSecureApduExchange(IsoDep isoDep, SecureMessaging secureMessaging)
//{
//    try
//    {
//        Console.WriteLine("🔹 Starting Secure APDU Exchange Test...");

//        // Example APDU: Read first 8 bytes of DG1 (Document Data)
//        byte[] readBinaryHeader = new byte[] { 0x00, 0xB0, 0x00, 0x00 }; // ReadBinary Command
//        byte[] expectedResponseLength = new byte[] { 0x08 }; // Expect 8 bytes back

//        // 🔹 Secure APDU Protection
//        byte[] secureApdu = secureMessaging.ProtectCommand(readBinaryHeader, null, expectedResponseLength);
//        Console.WriteLine($"🔹 Secure APDU (Encrypted): {BitConverter.ToString(secureApdu)}");

//        // 🔹 Send Secure APDU
//        byte[] responseApdu = await isoDep.TransceiveAsync(secureApdu);
//        Console.WriteLine($"🔹 Received Encrypted Response (Raw APDU): {BitConverter.ToString(responseApdu)}"); // ✅ Log full response

//        // 🔹 Process Secure Response
//        byte[] decryptedResponse = secureMessaging.UnprotectResponse(responseApdu);
//        Console.WriteLine($"🔹 Decrypted Response: {BitConverter.ToString(decryptedResponse)}");
//    }
//    catch (Exception ex)
//    {
//        Console.WriteLine($"❌ Secure APDU Test Failed: {ex.Message}");
//    }
//}
