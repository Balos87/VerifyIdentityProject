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
            var checkUser = await _userManager.FindByEmailAsync(registerDTO.Email);
            if (checkUser != null)
            {
                return BadRequest("User already exists");
            }
            var result = await _userService.Register(registerDTO);
            if (result.Succeeded)
            {
                return Ok(result);
            }
            return BadRequest(result);
        }

        [HttpPost]
        [Route("/user/login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDTO)
        {
            var result = await _userService.Login(loginDTO);
            if (result)
            {
                return Ok("Login successful");
            }
            return BadRequest("Login failed");
        }
    }
}
