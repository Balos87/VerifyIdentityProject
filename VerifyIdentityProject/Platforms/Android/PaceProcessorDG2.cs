using Android.Nfc.Tech;
using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Platforms.Android.AndroidHelpers;

namespace VerifyIdentityProject.Platforms.Android
{
    public class PaceProcessorDG2
    {
        private readonly IsoDep _isoDep;
        private static byte[] AID_MRTD = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
        private static byte[] ImgBytes;
        public PaceProcessorDG2(IsoDep isoDep)
        {
            _isoDep = isoDep;
        }

        // Main method to perform PACE
        public static async Task<byte[]> PerformPaceDG2Async(IsoDep isoDep, string apiUrl)
        {
            Console.WriteLine("<-PerformPace DG2->");
            try
            {
                // Step 0: Select the passport application
                PaceHelper.SelectApplicationPace(isoDep);

                // Step 1: Read CardAccess to get PACE parameters
                var cardAccess = PaceHelper.ReadCardAccessPace(isoDep);
                var validOids = PaceHelper.ValidateAndListPACEInfoWithDescriptionsPace(cardAccess);
                Console.WriteLine($"");
                Console.WriteLine("______Valid PACE Protocols:");

                // Fetch MRZ data from secrets
                var secrets = GetSecrets.FetchSecrets();
                var mrzData = secrets?.MRZ_NUMBERS ?? string.Empty;
                Console.WriteLine($"mrzData: {mrzData}");

                byte[] imgBytes = null;

                foreach (var oid in validOids)
                {
                    if (OidHelper.OidEndsWith(oid, "4.2.4"))
                    {
                        Console.WriteLine($"OID: {BitConverter.ToString(oid)}");

                        // Step 2: Perform PACE protocol
                        var pace = new PaceProtocol(isoDep, mrzData, oid);
                        bool success = pace.PerformPaceProtocol();
                        var (KSEnc, KSMac) = pace.GetKsEncAndKsMac();
                        Console.WriteLine(success ? "PACE-authentication succeeded!" : "PACE-authentication failed");

                        // Step 3: Perform Secure Messaging
                        var secureMessage = new SecureMessage(KSEnc, KSMac, isoDep);

                        // Step 4: Select eMRTD application with secure messaging
                        var selectApplication = secureMessage.SelectApplication();

                        // Step 5: Select and read EF.DG2 with secure messaging (awaiting the async call)
                        imgBytes = await secureMessage.SelectDG2Async(apiUrl);

                    }
                }
                Console.WriteLine("");
                Console.WriteLine("<---------------------------------------->");

                return imgBytes ?? throw new Exception("No image data retrieved.");
            }
            catch (Exception ex)
            {
                throw new PaceException("The PACE process failed", ex);
            }
        }
    }
}
