using Microsoft.AspNetCore.Identity;
using VerifyIdentityAPI.Models.DTOs;

namespace VerifyIdentityAPI.Services.IServices
{
    public interface IUserService
    {
        Task<bool> Login(LoginDTO loginDTO);
        Task<IdentityResult> Register(RegisterDTO registerDTO);
    }
}
