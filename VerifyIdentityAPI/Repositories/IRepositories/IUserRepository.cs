using Microsoft.AspNetCore.Identity;
using VerifyIdentityAPI.Models;
using VerifyIdentityAPI.Models.DTOs;

namespace VerifyIdentityAPI.Repositories.IRepositories
{
    public interface IUserRepository
    {
        Task<bool> LoginAsync(LoginDTO loginDTO);

        Task<IdentityResult> RegisterAsync(RegisterDTO registerDTO);

        Task<User> FindUserByEmailAsync(string email);

        Task<List<User>> GetAllUsersAsync();
    }
}
