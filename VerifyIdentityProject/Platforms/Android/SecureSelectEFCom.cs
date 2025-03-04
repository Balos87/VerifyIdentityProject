using System;
using System.Linq;
using System.Threading.Tasks;
using Android.Nfc.Tech;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureSelectEFCom
    {
        private readonly IsoDep _isoDep;
        private readonly SecureMessaging _secureMessaging;

        public SecureSelectEFCom(IsoDep isoDep, SecureMessaging secureMessaging)
        {
            _isoDep = isoDep ?? throw new ArgumentNullException(nameof(isoDep));
            _secureMessaging = secureMessaging ?? throw new ArgumentNullException(nameof(secureMessaging));
        }

        public async Task<bool> SelectEFComAsync()
        {
            try
            {
                Console.WriteLine("🔹 Starting Secure SELECT EF.COM...");

                // 🔹 Step 1: Create the Unprotected SELECT APDU for EF.COM
                // Unprotected APDU components:
                byte[] header = new byte[] { 0x00, 0xA4, 0x02, 0x0C };
                byte[] data = new byte[] { 0x01, 0x1E }; // File identifier for EF.COM
                Console.WriteLine($"🔹 Unprotected SELECT EF.COM APDU: {BitConverter.ToString(header)+(data)}");

                // 🔹 Step 2: Secure Messaging - Protect the Command
                byte[] secureApdu = _secureMessaging.ProtectCommand(header, data, null);
                Console.WriteLine($"🔹 Secure SELECT EF.COM APDU (Encrypted): {BitConverter.ToString(secureApdu)}");

                // 🔹 Step 3: Send Secure APDU
                byte[] responseApdu = await _isoDep.TransceiveAsync(secureApdu);
                Console.WriteLine($"🔹 Received Encrypted Response: {BitConverter.ToString(responseApdu)}");

                // 🔹 Step 4: Validate Response
                if (responseApdu == null || responseApdu.Length < 2)
                {
                    Console.WriteLine("❌ Invalid response (null or too short). EF.COM selection failed.");
                    return false;
                }

                // 🔹 Step 5: Extract SW1 SW2 (Status Words)
                byte sw1 = responseApdu[responseApdu.Length - 2];
                byte sw2 = responseApdu[responseApdu.Length - 1];
                Console.WriteLine($"🔹 Status Word (SW1 SW2): {sw1:X2} {sw2:X2}");

                // 🔹 Step 6: Verify Response MAC
                if (!_secureMessaging.VerifyResponseMAC(responseApdu))
                {
                    Console.WriteLine("❌ MAC verification failed. Data may be tampered with!");
                    return false;
                }
                Console.WriteLine("✅ MAC verification successful!");

                // 🔹 Step 7: Check If Selection Was Successful (`90 00`)
                if (sw1 == 0x90 && sw2 == 0x00)
                {
                    Console.WriteLine("✅ EF.COM selected successfully!");
                    return true;
                }
                else
                {
                    Console.WriteLine($"❌ EF.COM selection failed. Status: {sw1:X2} {sw2:X2}");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Secure SELECT EF.COM Failed: {ex.Message}");
                return false;
            }
        }

        // 🔹 Method to Read EF.COM File
        private async Task<byte[]> ReadEfComFile()
        {
            Console.WriteLine("🔹 Reading EF.COM file...");

            byte[] readEfComHeader = new byte[] { 0x0C, 0xB0, 0x00, 0x00 }; // ReadBinary for EF.COM
            byte[] le = new byte[] { 0x00 }; // Expect all available bytes

            byte[] secureApdu = _secureMessaging.ProtectCommand(readEfComHeader, null, le);
            byte[] response = await _isoDep.TransceiveAsync(secureApdu);

            Console.WriteLine($"🔹 Received EF.COM response: {BitConverter.ToString(response)}");

            return _secureMessaging.UnprotectResponse(response);
        }

    }   
}

