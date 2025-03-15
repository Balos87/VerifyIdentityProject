using Android.Nfc.Tech;
using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Platforms.Android.AndroidHelpers;
using VerifyIdentityProject.Helpers.Exceptions;

namespace VerifyIdentityProject.Platforms.Android
{
    public class PaceProcessorDG2 : PaceProcessorBase
    {
        public PaceProcessorDG2(IsoDep isoDep) : base(isoDep) { }

        public async Task<byte[]> PerformPaceDG2Async(string apiUrl)
        {
            Console.WriteLine("👉🏽 PerformPace DG2");
            Console.WriteLine("Debug101 PerformPaceDG2Async");

            try
            {
                SecureMessage secureMessage = PerformCommonPace(_isoDep);

                // Step 6: Select and read EF.DG2 with secure messaging
                var imgBytes = await secureMessage.SelectDG2Async(apiUrl);

                Console.WriteLine("\n➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");

                return imgBytes ?? throw new PaceException(PaceException.MessageText);
            }
            catch (Exception ex)
            {
                if (!_isoDep.IsConnected)
                {
                    Console.WriteLine(NfcTagLostException.MessageText);
                    throw new NfcTagLostException(ex);
                }

                Console.WriteLine(PaceException.MessageText);
                throw new PaceException(ex);
            }
        }
    }
}