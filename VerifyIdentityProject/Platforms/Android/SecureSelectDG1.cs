using System;
using System.Linq;
using System.Threading.Tasks;
using Android.Nfc.Tech;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureSelectDG1
    {
        private readonly IsoDep _isoDep;
        private readonly SecureMessaging _secureMessaging;

        public SecureSelectDG1(IsoDep isoDep, SecureMessaging secureMessaging)
        {
            _isoDep = isoDep ?? throw new ArgumentNullException(nameof(isoDep));
            _secureMessaging = secureMessaging ?? throw new ArgumentNullException(nameof(secureMessaging));
        }

        public async Task<bool> SelectDG1Async()
        {
            try
            {
                Console.WriteLine("🔹 Starting Secure SELECT DG1...");

                // Unprotected APDU components:
                // Header: CLA, INS, P1, P2
                byte[] header = new byte[] { 0x00, 0xA4, 0x02, 0x0C };
                // Data: file identifier for DG1. (Here we assume DG1 is identified by 0x01, 0x01.
                // Adjust this if your DG1 file ID is different.)
                byte[] data = new byte[] { 0x01, 0x01 };

                // Log the unprotected APDU (print both header and data in hex)
                Console.WriteLine($"🔹 Unprotected SELECT DG1 APDU: {BitConverter.ToString(header)} {BitConverter.ToString(data)}");

                // Build the secure APDU using our SecureMessaging class
                byte[] secureApdu = _secureMessaging.ProtectCommand(header, data, null);
                Console.WriteLine($"🔹 Secure SELECT DG1 APDU (Encrypted): {BitConverter.ToString(secureApdu)}");

                // Send the secure APDU to the card via IsoDep
                byte[] responseApdu = await _isoDep.TransceiveAsync(secureApdu);
                Console.WriteLine($"🔹 Received Encrypted Response: {BitConverter.ToString(responseApdu)}");

                // Validate the response: must be non-null and at least 2 bytes (SW1 and SW2)
                if (responseApdu == null || responseApdu.Length < 2)
                {
                    Console.WriteLine("❌ Invalid response (null or too short). DG1 selection failed.");
                    return false;
                }

                // Extract the status word (SW1, SW2)
                byte sw1 = responseApdu[responseApdu.Length - 2];
                byte sw2 = responseApdu[responseApdu.Length - 1];
                Console.WriteLine($"🔹 Status Word (SW1 SW2): {sw1:X2} {sw2:X2}");

                // Verify the response MAC using SecureMessaging's method
                if (!_secureMessaging.VerifyResponseMAC(responseApdu))
                {
                    Console.WriteLine("❌ MAC verification failed. Data may be tampered with!");
                    return false;
                }
                Console.WriteLine("✅ MAC verification successful!");

                // Check if the selection was successful (90-00 indicates success)
                if (sw1 == 0x90 && sw2 == 0x00)
                {
                    Console.WriteLine("✅ DG1 selected successfully!");
                    return true;
                }
                else
                {
                    Console.WriteLine($"❌ DG1 selection failed. Status: {sw1:X2} {sw2:X2}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Secure SELECT DG1 Failed: {ex.Message}");
                return false;
            }
        }
    }
}
