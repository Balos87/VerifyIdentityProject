namespace VerifyIdentityAspFrontend.Models.Verification
{
    public class PendingVerification
    {
        public string Token { get; set; }
        public string UserId { get; set; }
        public DateTime ExpiresAt { get; set; }
    }

}
