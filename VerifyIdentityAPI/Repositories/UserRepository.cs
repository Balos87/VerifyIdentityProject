using Microsoft.AspNetCore.Identity;
using VerifyIdentityAPI.Models;
using VerifyIdentityAPI.Models.DTOs;
using VerifyIdentityAPI.Repositories.IRepositories;

namespace VerifyIdentityAPI.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly UserManager<User> _userManager;

        public UserRepository(UserManager<User> userManager)
        {
            _userManager = userManager;
        }
        public async Task<bool> Login(LoginDTO loginDTO)
        {
            var user = await _userManager.FindByEmailAsync(loginDTO.Email);
            if(user== null)
            {
                return false;
            }
            return await _userManager.CheckPasswordAsync(user, loginDTO.Password);
        }

        public Task<IdentityResult> Register(RegisterDTO registerDTO)
        {
            var user = new User
            {
                Email = registerDTO.Email,
                UserName = registerDTO.Email,
                FirstName = registerDTO.FirstName,
                LastName = registerDTO.LastName,
                BirthDate = registerDTO.BirthDate
            };
            return _userManager.CreateAsync(user, registerDTO.Password);
        }
    }
}
