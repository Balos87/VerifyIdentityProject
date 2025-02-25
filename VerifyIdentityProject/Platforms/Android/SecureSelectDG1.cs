//using System;
//using System.Linq;
//using System.Threading.Tasks;
//using Android.Nfc.Tech;

//namespace VerifyIdentityProject.Platforms.Android
//{
//    public class SecureSelectDG1
//    {
//        private readonly IsoDep _isoDep;
//        private readonly SecureMessaging _secureMessaging;

//        public SecureSelectDG1(IsoDep isoDep, SecureMessaging secureMessaging)
//        {
//            _isoDep = isoDep ?? throw new ArgumentNullException(nameof(isoDep));
//            _secureMessaging = secureMessaging ?? throw new ArgumentNullException(nameof(secureMessaging));
//        }

//        public async Task<bool> SelectDG1Async()
//        {
//            try
//            {
//                Console.WriteLine("\n🔹 Starting Secure SELECT DG1...");

//                // Unprotected APDU components:
//                byte[] header = new byte[] { 0x00, 0xA4, 0x02, 0x0C }; // CLA, INS, P1, P2
//                byte[] data = new byte[] { 0x01, 0x01 }; // File ID for DG1

//                Console.WriteLine($"🔹 Unprotected SELECT DG1 APDU: {BitConverter.ToString(header)} {BitConverter.ToString(data)}");

//                // Securely wrap the APDU using SecureMessaging
//                byte[] secureApdu = _secureMessaging.ProtectCommand(header, data, null);
//                Console.WriteLine($"🔹 Secure SELECT DG1 APDU (Encrypted): {BitConverter.ToString(secureApdu)}");

//                // Send the secure APDU to the chip
//                byte[] responseApdu = await _isoDep.TransceiveAsync(secureApdu);
//                Console.WriteLine($"🔹 Received Encrypted Response: {BitConverter.ToString(responseApdu)}");

//                if (responseApdu == null || responseApdu.Length < 2)
//                {
//                    Console.WriteLine("❌ Error: Response APDU is null or too short. DG1 selection failed.");
//                    return false;
//                }

//                // Extract the status word (SW1, SW2)
//                byte sw1 = responseApdu[responseApdu.Length - 2];
//                byte sw2 = responseApdu[responseApdu.Length - 1];
//                Console.WriteLine($"🔹 Status Word (SW1 SW2): {sw1:X2} {sw2:X2}");

//                // If response is an error, print its meaning
//                if (sw1 == 0x69 && sw2 == 0x82)
//                {
//                    Console.WriteLine("❌ Error: Security status not satisfied (69 82). This might indicate missing authentication.");
//                }
//                else if (sw1 == 0x6A && sw2 == 0x82)
//                {
//                    Console.WriteLine("❌ Error: File not found (6A 82). DG1 might not be selectable using SELECT.");
//                }
//                else if (sw1 == 0x68 && sw2 == 0x82)
//                {
//                    Console.WriteLine("❌ Error: Secure messaging object missing (68 82). Secure messaging might not be applied correctly.");
//                }

//                // Verify the response MAC
//                if (!_secureMessaging.VerifyResponseMAC(responseApdu))
//                {
//                    Console.WriteLine("❌ MAC verification failed. Possible data tampering detected!");
//                    return false;
//                }
//                Console.WriteLine("✅ MAC verification successful!");

//                // Check for success (90 00)
//                if (sw1 == 0x90 && sw2 == 0x00)
//                {
//                    Console.WriteLine("✅ DG1 successfully selected!");
//                    return true;
//                }
//                else
//                {
//                    Console.WriteLine($"❌ DG1 selection failed. Status: {sw1:X2} {sw2:X2}");
//                    return false;
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine($"❌ Exception in Secure SELECT DG1: {ex.Message}");
//                return false;
//            }
//        }
//    }
//}
using Android.Nfc.Tech;

public class SecureSelectDG1
{
    private readonly IsoDep _isoDep;

    public SecureSelectDG1(IsoDep isoDep)
    {
        _isoDep = isoDep ?? throw new ArgumentNullException(nameof(isoDep));
    }

    public async Task<bool> SelectDG1Async()
    {
        try
        {
            Console.WriteLine("\n🔹 Starting Unprotected SELECT DG1...");

            // Unprotected APDU components:
            byte[] header = new byte[] { 0x00, 0xA4, 0x02, 0x0C }; // CLA, INS, P1, P2
            byte[] fileId = new byte[] { 0x01, 0x01 };                // File ID for DG1
            byte lc = (byte)fileId.Length;                           // Lc = 0x02

            // Build the unprotected SELECT DG1 APDU: header || Lc || fileId (without Le)
            byte[] selectDG1Apdu = header
                .Concat(new byte[] { lc })
                .Concat(fileId)
                .ToArray();

            Console.WriteLine($"🔹 Unprotected SELECT DG1 APDU: {BitConverter.ToString(selectDG1Apdu)}");

            // Send the unprotected APDU directly to the chip
            byte[] responseApdu = await _isoDep.TransceiveAsync(selectDG1Apdu);
            Console.WriteLine($"🔹 Received Response: {BitConverter.ToString(responseApdu)}");

            if (responseApdu == null || responseApdu.Length < 2)
            {
                Console.WriteLine("❌ Error: Response APDU is null or too short. DG1 selection failed.");
                return false;
            }

            // Extract the status word (SW1, SW2)
            byte sw1 = responseApdu[responseApdu.Length - 2];
            byte sw2 = responseApdu[responseApdu.Length - 1];
            Console.WriteLine($"🔹 Status Word (SW1 SW2): {sw1:X2} {sw2:X2}");

            if (sw1 == 0x90 && sw2 == 0x00)
            {
                Console.WriteLine("✅ DG1 successfully selected!");
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
            Console.WriteLine($"❌ Exception in Unprotected SELECT DG1: {ex.Message}");
            return false;
        }
    }
}
