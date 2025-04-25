namespace VerifyIdentityAspFrontend.Models
{
    public class VerifyOperation
    {
        public Guid Id { get; set; }
        public string SessiondId { get; set; } = string.Empty;

        public Status Status { get; set; } = Status.Pending;

        // FK
        public string UserId { get; set; } = string.Empty;

        //nav back to the user
        public ApplicationUser? User { get; set; }

        public DateTime QrCreated { get; set; } = DateTime.UtcNow;
        public DateTime QrExpired { get; set; } = DateTime.UtcNow.AddHours(10);
    }

    public enum Status
    {
        Pending,
        Success,
        Denied
    }
}
