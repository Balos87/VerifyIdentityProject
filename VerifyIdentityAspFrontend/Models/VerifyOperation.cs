namespace VerifyIdentityAspFrontend.Models
{
    public class VerifyOperation
    {
        public Guid Id { get; set; }
        public string SessiondId { get; set; }
        public Status Status { get; set; } = Status.Pending;
        public string UserId { get; set; }
        public DateTime QrCreated { get; set; } = DateTime.UtcNow;
        public DateTime QrExpired { get; set; } = DateTime.UtcNow.AddMinutes(10);

    }
    public enum Status
    {
        Pending,
        Success,
        Denied
    }
}
