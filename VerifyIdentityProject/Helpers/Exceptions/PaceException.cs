using System;

namespace VerifyIdentityProject.Helpers.Exceptions
{
    public class PaceException : Exception
    {
        private const string DefaultMessage = "❌ Error while performing PACE: ";

        public PaceException() : base(DefaultMessage) { }

        public PaceException(Exception inner) : base(DefaultMessage, inner) { }

        public PaceException(string message) : base(message) { }

        public PaceException(string message, Exception inner) : base(message, inner) { }

        public static string MessageText => DefaultMessage;
    }
}
