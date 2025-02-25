//using Android.Nfc.Tech;
//using System;
//using System.Threading.Tasks;

//namespace VerifyIdentityProject.Platforms.Android
//{
//    public class SecureReadDG1
//    {
//        private readonly IsoDep _isoDep;
//        private readonly SecureMessaging _secureMessaging;

//        public SecureReadDG1(IsoDep isoDep, SecureMessaging secureMessaging)
//        {
//            _isoDep = isoDep ?? throw new ArgumentNullException(nameof(isoDep));
//            _secureMessaging = secureMessaging ?? throw new ArgumentNullException(nameof(secureMessaging));
//        }

//        public async Task<byte[]> ReadDG1Async()
//        {
//            try
//            {
//                Console.WriteLine("🔹 Starting Secure READ DG1...");

//                // Construct a READ BINARY command for DG1.
//                // DG1 is typically read using 00 B0 00 00 Le, where Le = 0x00 (full length).
//                byte[] readBinaryHeader = new byte[] { 0x00, 0xB0, 0x00, 0x00 };
//                byte[] le = new byte[] { 0x00 };

//                Console.WriteLine($"🔹 Unprotected READ DG1 APDU: {BitConverter.ToString(readBinaryHeader)} {BitConverter.ToString(le)}");

//                // Protect the APDU using secure messaging.
//                byte[] secureApdu = _secureMessaging.ProtectCommand(readBinaryHeader, null, le);
//                Console.WriteLine($"🔹 Secure READ DG1 APDU (Encrypted): {BitConverter.ToString(secureApdu)}");

//                // Send the secure APDU to the card.
//                byte[] responseApdu = await _isoDep.TransceiveAsync(secureApdu);
//                Console.WriteLine($"🔹 Received Encrypted Response: {BitConverter.ToString(responseApdu)}");

//                // Validate the response length before processing.
//                if (responseApdu == null || responseApdu.Length < 2)
//                {
//                    Console.WriteLine("❌ Received invalid response (null or too short). DG1 read failed.");
//                    return null;
//                }

//                // Extract the status word (SW1, SW2).
//                byte sw1 = responseApdu[responseApdu.Length - 2];
//                byte sw2 = responseApdu[responseApdu.Length - 1];
//                Console.WriteLine($"🔹 Status Word (SW1 SW2): {sw1:X2} {sw2:X2}");

//                // Check if a secure messaging object (e.g., MAC or encryption) is missing.
//                if (sw1 == 0x69 && sw2 == 0x87)
//                {
//                    Console.WriteLine("❌ Error 69 87: Secure messaging object missing.");
//                    return null;
//                }

//                // Check if access to DG1 is denied due to security conditions.
//                if (sw1 == 0x69 && sw2 == 0x82)
//                {
//                    Console.WriteLine("❌ Error 69 82: Access conditions not satisfied.");
//                    return null;
//                }

//                // Check if DG1 cannot be selected with READ BINARY.
//                if (sw1 == 0x68 && sw2 == 0x82)
//                {
//                    Console.WriteLine("❌ Error 68 82: Secure messaging required, or DG1 is not selectable via READ BINARY.");
//                    return null;
//                }

//                // Unprotect the response to extract the decrypted DG1 data.
//                byte[] dg1Data = _secureMessaging.UnprotectResponse(responseApdu);
//                Console.WriteLine($"🔹 Decrypted DG1 Data: {BitConverter.ToString(dg1Data)}");

//                // Validate the decrypted data.
//                if (dg1Data == null || dg1Data.Length < 2)
//                {
//                    Console.WriteLine("❌ DG1 read failed: Decrypted data is empty or too short.");
//                    return null;
//                }

//                // Check the status word in the decrypted response.
//                int length = dg1Data.Length;
//                byte sw1Decrypted = dg1Data[length - 2];
//                byte sw2Decrypted = dg1Data[length - 1];
//                Console.WriteLine($"🔹 Decrypted Status Word (SW1 SW2): {sw1Decrypted:X2} {sw2Decrypted:X2}");

//                // Check if DG1 read was successful (SW = 90 00).
//                if (sw1Decrypted == 0x90 && sw2Decrypted == 0x00)
//                {
//                    Console.WriteLine("✅ DG1 read successfully!");
//                    return dg1Data.Take(length - 2).ToArray(); // Remove status word from data
//                }
//                else
//                {
//                    Console.WriteLine($"❌ DG1 read failed. Status: {sw1Decrypted:X2} {sw2Decrypted:X2}");
//                    return null;
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine($"❌ Secure READ DG1 Failed: {ex.Message}");
//                return null;
//            }
//        }
//    }
//}

using Android.Nfc.Tech;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureReadDG1
    {
        private readonly IsoDep _isoDep;
        private readonly SecureMessaging _secureMessaging;
        // Maximum number of data bytes to read per command. Adjust if needed.
        private const int ChunkSize = 0xFF;

        public SecureReadDG1(IsoDep isoDep, SecureMessaging secureMessaging)
        {
            _isoDep = isoDep ?? throw new ArgumentNullException(nameof(isoDep));
            _secureMessaging = secureMessaging ?? throw new ArgumentNullException(nameof(secureMessaging));
        }

        /// <summary>
        /// Reads DG1 using READ BINARY with secure messaging.
        /// First, a short header (e.g. 4 bytes) is read to determine total length.
        /// Then, the remainder is read in segments.
        /// </summary>
        public async Task<byte[]> ReadDG1Async()
        {
            try
            {
                Console.WriteLine("🔹 Starting Secure READ DG1...");

                // --- Step 1: Read header (first 4 bytes) to get length info ---
                // Build a READ BINARY command for offset 0 reading 4 bytes.
                // Standard READ BINARY: CLA=00, INS=B0, P1=P2=offset, Le=length.
                byte[] headerApdu = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x04 };
                // Wrap the APDU (secure messaging uses header (first 4 bytes) and separate Le)
                byte[] secureHeaderApdu = _secureMessaging.ProtectCommand(headerApdu.Take(4).ToArray(), null, new byte[] { 0x04 });
                Console.WriteLine($"🔹 Secure READ DG1 Header APDU: {BitConverter.ToString(secureHeaderApdu)}");

                byte[] headerResponse = await _isoDep.TransceiveAsync(secureHeaderApdu);
                Console.WriteLine($"🔹 Received Encrypted Header Response: {BitConverter.ToString(headerResponse)}");
                byte[] decryptedHeader = _secureMessaging.UnprotectResponse(headerResponse);
                Console.WriteLine($"🔹 Decrypted DG1 Header: {BitConverter.ToString(decryptedHeader)}");

                // --- Step 2: Determine total length from header ---
                // Assume TLV format: first byte = tag, second byte = length.
                if (decryptedHeader.Length < 2)
                {
                    Console.WriteLine("❌ DG1 header too short.");
                    return null;
                }
                int dataLength = decryptedHeader[1];
                // Total file length includes the tag and length bytes.
                int totalLength = dataLength + 2;
                Console.WriteLine($"🔹 Total DG1 Length (including TLV header): {totalLength} bytes");

                // --- Step 3: Read full DG1 in segments ---
                List<byte> fullData = new List<byte>();
                int offset = 0;
                while (offset < totalLength)
                {
                    // Calculate how many bytes to read in this chunk.
                    int remaining = totalLength - offset;
                    int readLen = remaining > ChunkSize ? ChunkSize : remaining;

                    // Build READ BINARY command with proper offset.
                    byte p1 = (byte)(offset >> 8);
                    byte p2 = (byte)(offset & 0xFF);
                    byte[] readBinaryApdu = new byte[] { 0x00, 0xB0, p1, p2, (byte)readLen };
                    byte[] secureApdu = _secureMessaging.ProtectCommand(readBinaryApdu.Take(4).ToArray(), null, new byte[] { (byte)readLen });
                    Console.WriteLine($"🔹 Secure READ DG1 APDU for offset {offset}: {BitConverter.ToString(secureApdu)}");

                    byte[] responseApdu = await _isoDep.TransceiveAsync(secureApdu);
                    Console.WriteLine($"🔹 Received Encrypted Response at offset {offset}: {BitConverter.ToString(responseApdu)}");
                    byte[] decryptedChunk = _secureMessaging.UnprotectResponse(responseApdu);
                    Console.WriteLine($"🔹 Decrypted Chunk: {BitConverter.ToString(decryptedChunk)}");

                    // Remove trailing status word if present.
                    if (decryptedChunk.Length >= 2)
                    {
                        int chunkLen = decryptedChunk.Length;
                        byte sw1 = decryptedChunk[chunkLen - 2];
                        byte sw2 = decryptedChunk[chunkLen - 1];
                        if (sw1 == 0x90 && sw2 == 0x00)
                        {
                            decryptedChunk = decryptedChunk.Take(chunkLen - 2).ToArray();
                        }
                    }
                    fullData.AddRange(decryptedChunk);
                    offset += readLen;
                }

                Console.WriteLine($"🔹 Full DG1 Data Read: {BitConverter.ToString(fullData.ToArray())}");
                return fullData.ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Secure READ DG1 Failed: {ex.Message}");
                return null;
            }
        }
    }
}
