using Android.Nfc.Tech;
using VerifyIdentityProject.Helpers;

namespace VerifyIdentityProject.Platforms.Android
{
    public class PaceProcessorDG1 : PaceProcessorBase
    {
        public PaceProcessorDG1(IsoDep isoDep) : base(isoDep) { }

        public Dictionary<string, string> PerformPaceDG1()
        {
            Console.WriteLine("👉🏽PerformPace DG1\n");

            try
            {
                SecureMessage secureMessage = PerformCommonPace(_isoDep);

                // Step 6: Select and read EF.DG1 with secure messaging
                var mrz = secureMessage.SelectDG1();
                _isoDep.Close();

                Console.WriteLine("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");

                return mrz;
            }
            catch (Exception ex)
            {
                throw new PaceException("The PACE process for DG1 failed", ex);
            }
        }
    }
}
