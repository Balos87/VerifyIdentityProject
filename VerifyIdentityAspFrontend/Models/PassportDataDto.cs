namespace VerifyIdentityAspFrontend.Models
{
    public class PassportDataDto
    {
        public Guid OperationId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string SSN { get; set; }
    }

}
