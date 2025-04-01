using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using VerifyIdentityAPI.Models;
using VerifyIdentityAPI.Models.DTOs;
using VerifyIdentityAPI.Services.IServices;

namespace VerifyIdentityAPI.Controllers
{
    [Controller]
    public class UserController : Controller
    {
        private readonly IUserService _userService;
        private readonly UserManager<User> _userManager;
        public UserController(IUserService userService, UserManager<User> userManager)
        {
            _userManager = userManager;
            _userService = userService;
        }

        [HttpPost]
        [Route("/user/register")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDTO)
        {
            try
            {
                var checkUser = await _userManager.FindByEmailAsync(registerDTO.Email);
                if (checkUser != null)
                {
                    return BadRequest("User already exists");
                }
                var result = await _userService.RegisterAsync(registerDTO);
                if (result.Succeeded)
                {
                    return Ok(result);
                }
                else
                {
                    return BadRequest("Registration failed");
                }
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost]
        [Route("/user/login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDTO)
        {
            try
            {
                var result = await _userService.LoginAsync(loginDTO);
                return Ok(result);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet]
        [Route("/user/{email}")]
        public async Task<IActionResult> GetUserByEmail(string email)
        {
            try
            {
                var user = await _userService.FindUserByEmailAsync(email);
                return Ok(user);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet]
        [Route("/user/all")]
        public async Task<IActionResult> GetAllUsers()
        {
            try
            {
                var users = await _userService.GetAllUsersAsync();
                return Ok(users);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
