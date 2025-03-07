using Android.Nfc.Tech;
using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Platforms.Android.AndroidHelpers;

namespace VerifyIdentityProject.Platforms.Android
{
    public class PaceProcessorDG2 : PaceProcessorBase
    {
        public PaceProcessorDG2(IsoDep isoDep) : base(isoDep) { }

        public async Task<byte[]> PerformPaceDG2Async(string apiUrl)
        {
            Console.WriteLine("<-PerformPace DG2->");

            try
            {
                SecureMessage secureMessage = PerformCommonPace(_isoDep);

                // Step 6: Select and read EF.DG2 with secure messaging
                var imgBytes = await secureMessage.SelectDG2Async(apiUrl);

                Console.WriteLine("\n<---------------------------------------->");

                return imgBytes ?? throw new Exception("No image data retrieved.");
            }
            catch (Exception ex)
            {
                throw new PaceException("The PACE process for DG2 failed", ex);
            }
        }
    }
}
