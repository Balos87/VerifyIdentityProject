using System;

namespace VerifyIdentityProject.Helpers.Exceptions
{
    public class NfcTagLostException : Exception
    {
        private const string DefaultMessage = "⚠️ NFC connection was lost, hold the device still during process. Please restart.";

        public NfcTagLostException(Exception innerException = null)
            : base(DefaultMessage, innerException)
        {
        }

        public static string MessageText => DefaultMessage;
    }
}
