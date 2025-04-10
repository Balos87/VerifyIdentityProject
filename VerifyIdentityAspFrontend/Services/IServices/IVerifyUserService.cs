namespace VerifyIdentityAspFrontend.Services.IServices
{
    public interface IVerifyUserService
    {
        Task<bool> CheckUserDataAsync(UserDTO userDTO);
    }

    public class UserDTO
    {
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string SSN { get; set; }
        public string SessionId { get; set; }
    }

}
