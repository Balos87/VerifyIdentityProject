using Microsoft.AspNetCore.Identity;
using VerifyIdentityAPI.Models;
using VerifyIdentityAPI.Models.DTOs;
using VerifyIdentityAPI.Models.ViewModels;
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

        public async Task<bool> LoginAsync(LoginDTO loginDTO)
        {
           return await _userRepository.LoginAsync(loginDTO);
        }

        public async Task<IdentityResult> RegisterAsync(RegisterDTO registerDTO)
        {
           return await _userRepository.RegisterAsync(registerDTO);
        }

        public async Task<UserShowVM> FindUserByEmailAsync(string email)
        {
           var user = await _userRepository.FindUserByEmailAsync(email);

            if(user == null)
            {
                throw new Exception("User not found");
            }

            var userDto = new UserShowVM
            {
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                BirthDate = user.BirthDate,
                PhoneNumber = user.PhoneNumber,
                Quizzes = user?.Quizzes?.Select(q=> new QuizShowVMUser
                {
                    Name = q.Name
                }).ToList()
            };
            return userDto;
        }

        public async Task<List<UserShowVM>> GetAllUsersAsync()
        {
            var usersList = await _userRepository.GetAllUsersAsync();
            List<UserShowVM> userVMList = new List<UserShowVM>();

            foreach (User user in usersList)
            {
                userVMList.Add(new UserShowVM
                {
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    BirthDate = user.BirthDate,
                    PhoneNumber = user.PhoneNumber,
                    Quizzes = user?.Quizzes?.Select(q=> new QuizShowVMUser
                    {
                        Name = q.Name
                    }).ToList()
                });
            }
            return userVMList;
        }
    }
}
