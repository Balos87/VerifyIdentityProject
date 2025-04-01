namespace VerifyIdentityAPI.Models.DTOs
{
    public class RegisterDTO
    {
        public required string Email { get; set; }
        public required string FirstName { get; set; }
        public required string LastName { get; set; }
        public required string BirthDate { get; set; }
        public required string Password { get; set; } 
        public required string ConfirmPassword { get; set; } 
    }
}
