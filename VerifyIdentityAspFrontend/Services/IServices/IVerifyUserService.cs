using VerifyIdentityAspFrontend.Models;

namespace VerifyIdentityAspFrontend.Services.IServices
{
    public interface IVerifyUserService
    {
        Task<bool> CheckUserDataAsync(UserDTO userDTO);
        Task<Status> ProcessVerificationAsync(Guid operationId, string firstName, string lastName, string ssn);
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
