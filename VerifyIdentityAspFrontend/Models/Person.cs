namespace VerifyIdentityAspFrontend.Models
{
    public class Person
    {
        public int Id { get; set; }

        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;

        public string SSN { get; set; } = string.Empty;

        public string UserId { get; set; } = string.Empty;

        // Optional: back-reference
        public ApplicationUser? User { get; set; }
    }
}
