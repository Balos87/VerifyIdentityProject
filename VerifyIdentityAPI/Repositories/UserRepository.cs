using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using VerifyIdentityAPI.Data;
using VerifyIdentityAPI.Models;
using VerifyIdentityAPI.Models.DTOs;
using VerifyIdentityAPI.Repositories.IRepositories;

namespace VerifyIdentityAPI.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly UserManager<User> _userManager;
        private readonly VerifyIdentityDbContext _context;
        public UserRepository(UserManager<User> userManager, VerifyIdentityDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        public async Task<bool> LoginAsync(LoginDTO loginDTO)
        {
            var user = await _userManager.FindByEmailAsync(loginDTO.Email);
            if(user== null)
            {
                return false;
            }
            return await _userManager.CheckPasswordAsync(user, loginDTO.Password);
        }

        public Task<IdentityResult> RegisterAsync(RegisterDTO registerDTO)
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

        public async Task<User> FindUserByEmailAsync(string email)
        {

            var user = await _context.Users.Include(u => u.UserQuizzes).ThenInclude(x=>x.Quiz).SingleOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                throw new Exception("User not found");
            }
            return user;
        }

        public async Task<List<User>> GetAllUsersAsync()
        {
            return await _context.Users.Include(u=>u.UserQuizzes).ThenInclude(x=>x.Quiz).ToListAsync();
        }
    }
}
