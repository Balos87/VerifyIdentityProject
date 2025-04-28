namespace VerifyIdentityAspFrontend.DTOs
{
    public class VerifyRequestDto
    {
        public string Token { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string SSN { get; set; }
    }

}
