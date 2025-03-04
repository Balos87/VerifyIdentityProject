using Android.Nfc.Tech;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureReadDG1
    {
        private readonly IsoDep _isoDep;
        private readonly SecureMessaging _secureMessaging;

        public SecureReadDG1(IsoDep isoDep, SecureMessaging secureMessaging)
        {
            _isoDep = isoDep ?? throw new ArgumentNullException(nameof(isoDep));
            _secureMessaging = secureMessaging ?? throw new ArgumentNullException(nameof(secureMessaging));
        }

        public async Task<byte[]> ReadDG1Async()
        {
            try
            {
                Console.WriteLine("🔹 Starting Secure READ DG1...");

                // Construct a READ BINARY command for DG1.
                // Note: DG1 is typically read with 00 B0 00 00 Le.
                // Le is set to 0x00 here to indicate that the entire file length is expected.
                byte[] readBinaryHeader = new byte[] { 0x00, 0xB0, 0x00, 0x00 };
                byte[] le = new byte[] { 0x00 };

                Console.WriteLine($"🔹 Unprotected READ DG1 APDU: {BitConverter.ToString(readBinaryHeader)} {BitConverter.ToString(le)}");

                // Protect the APDU with secure messaging.
                byte[] secureApdu = _secureMessaging.ProtectCommand(readBinaryHeader, null, le);
                Console.WriteLine($"🔹 Secure READ DG1 APDU (Encrypted): {BitConverter.ToString(secureApdu)}");

                // Transceive the command.
                byte[] responseApdu = await _isoDep.TransceiveAsync(secureApdu);
                Console.WriteLine($"🔹 Received Encrypted Response: {BitConverter.ToString(responseApdu)}");

                // Unprotect the response to extract the clear DG1 data.
                byte[] dg1Data = _secureMessaging.UnprotectResponse(responseApdu);
                Console.WriteLine($"🔹 Decrypted DG1 Data: {BitConverter.ToString(dg1Data)}");

                // Optionally, check the status word within the decrypted response.
                int length = dg1Data.Length;
                if (length >= 2)
                {
                    byte sw1 = dg1Data[length - 2];
                    byte sw2 = dg1Data[length - 1];
                    if (sw1 == 0x90 && sw2 == 0x00)
                    {
                        Console.WriteLine("✅ DG1 read successfully!");
                    }
                    else
                    {
                        Console.WriteLine($"❌ DG1 read failed. Status: {sw1:X2} {sw2:X2}");
                    }
                }
                return dg1Data;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Secure READ DG1 Failed: {ex.Message}");
                return null;
            }
        }
    }

}
