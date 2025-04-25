namespace VerifyIdentityAspFrontend.Services.IServices
{
    public interface IVerifyUserService
    {
        Task<bool> CheckUserDataAsync(UserDTO userDTO);
    }

    public class UserDTO
    {
        public string OperationId { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string SSN { get; set; }
    }

}
