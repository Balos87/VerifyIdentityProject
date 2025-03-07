using Android.Nfc.Tech;
using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Platforms.Android.AndroidHelpers;

namespace VerifyIdentityProject.Platforms.Android
{
    public class PaceProcessorDG1
    {
        private readonly IsoDep _isoDep;
        private static byte[] AID_MRTD = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
        private static Dictionary<string, string> _mrz;
        public PaceProcessorDG1(IsoDep isoDep)
        {
            _isoDep = isoDep;
        }

        // Main method to perform PACE
        public static Dictionary<string,string> PerformPaceDG1(IsoDep isoDep)
        {
            Console.WriteLine("<-PerformPace DG1->");
            try
            {
                // Step 1: Select the passport application
                PaceHelper.SelectApplicationPace(isoDep);

                // Step 2: Read CardAccess to get PACE parameters
                var cardAccess = PaceHelper.ReadCardAccessPace(isoDep);
                var validOids = PaceHelper.ValidateAndListPACEInfoWithDescriptionsPace(cardAccess);
                Console.WriteLine($"");
                Console.WriteLine("<-----Valid PACE Protocols---->");

                //Fetch mrz data from secrets
                var secrets = GetSecrets.FetchSecrets();
                var mrzData = secrets?.MRZ_NUMBERS ?? string.Empty;
                Console.WriteLine($"mrzData: {mrzData}");

                foreach (var oid in validOids)
                {
                    if (OidHelper.OidEndsWith(oid, "4.2.4"))
                    {
                        Console.WriteLine($"OID: {BitConverter.ToString(oid)}");

                        // Step 3: Perform PACE protocol
                        var pace = new PaceProtocol(isoDep, mrzData, oid);
                        bool success = pace.PerformPaceProtocol();
                        var (KSEnc, KSMac) = pace.GetKsEncAndKsMac();
                        Console.WriteLine(success ? "PACE-authentication succeeded!" : "PACE-authentication failed");

                        // Step 4: Perform Secure Messaging
                        var secureMessage = new SecureMessage(KSEnc, KSMac, isoDep);

                        // Step 5: Select eMRTD application with secure messaging
                        var selectApplication = secureMessage.SelectApplication();

                        // Step 6: Select and read EF.DG1 with secure messaging
                        _mrz = secureMessage.SelectDG1();
                        isoDep.Close();
                    }
                }
                Console.WriteLine("");
                Console.WriteLine("<---------------------------------------->");

                return _mrz;
            }
            catch (Exception ex)
            {
                throw new PaceException("The PACE process failed", ex);
            }
        }
    }
}
