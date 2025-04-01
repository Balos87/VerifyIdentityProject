using Microsoft.AspNetCore.Identity;
using VerifyIdentityAPI.Models;
using VerifyIdentityAPI.Models.DTOs;
using VerifyIdentityAPI.Models.ViewModels;

namespace VerifyIdentityAPI.Services.IServices
{
    public interface IUserService
    {
        Task<bool> LoginAsync(LoginDTO loginDTO);

        Task<IdentityResult> RegisterAsync(RegisterDTO registerDTO);

        Task<UserShowVM> FindUserByEmailAsync(string email);

        Task<List<UserShowVM>> GetAllUsersAsync();
    }
}
