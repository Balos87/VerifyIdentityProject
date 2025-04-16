using VerifyIdentityAspFrontend.Models.Verification;

namespace VerifyIdentityAspFrontend.Services
{
    public static class VerificationStore
    {
        public static Dictionary<string, PendingVerification> Verifications { get; } = new();
    }

}
