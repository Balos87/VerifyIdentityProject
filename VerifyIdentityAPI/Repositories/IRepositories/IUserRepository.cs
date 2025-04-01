using Microsoft.AspNetCore.Identity;
using VerifyIdentityAPI.Models.DTOs;

namespace VerifyIdentityAPI.Repositories.IRepositories
{
    public interface IUserRepository
    {
        Task<bool> Login(LoginDTO loginDTO);
        Task<IdentityResult> Register(RegisterDTO registerDTO);
    }
}
