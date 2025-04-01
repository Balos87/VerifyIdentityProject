using Microsoft.AspNetCore.Identity;
using VerifyIdentityAPI.Models.DTOs;
using VerifyIdentityAPI.Repositories.IRepositories;
using VerifyIdentityAPI.Services.IServices;

namespace VerifyIdentityAPI.Services
{
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;
        public UserService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public async Task<bool> Login(LoginDTO loginDTO)
        {
           return await _userRepository.Login(loginDTO);
        }

        public async Task<IdentityResult> Register(RegisterDTO registerDTO)
        {
           return await _userRepository.Register(registerDTO);
        }
    }
}
