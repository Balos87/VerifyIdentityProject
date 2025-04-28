using VerifyIdentityAspFrontend.Models;
using VerifyIdentityAspFrontend.Models.Verification;

namespace VerifyIdentityAspFrontend.Services
{
    public static class VerificationStore
    {
        public static Dictionary<string, VerifyOperation> Verifications = new();
    }

}
