using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using VerifyIdentityAspFrontend.Services.IServices;

namespace VerifyIdentityAspFrontend.Services
{
    public class VerifyUserService : IVerifyUserService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public VerifyUserService(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<bool> CheckUserDataAsync(UserDTO userDTO)
        {
            var user = await _userManager.FindByEmailAsync(userDTO.Email);
            if (user == null)
            {
                throw new Exception($"couldn't find user with email: {userDTO.Email}");
            }
            var sessId = _httpContextAccessor.HttpContext?.Session.Id;
            if (sessId != userDTO.SessionId)
            {
                throw new Exception($"SessionId didnt match. Incoming-id:{userDTO.SessionId} Stored-id: {sessId}");
            }
            var claims = new List<Claim>
            {
                new Claim("FirstName", userDTO.FirstName),
                new Claim("LastName", userDTO.LastName),
                new Claim("SSN", userDTO.SSN)
            };

            var result = await _userManager.AddClaimsAsync(user, claims);
            if(!result.Succeeded) return false;

            //login the user again so the claims gets into the session
            await _signInManager.SignInAsync(user, isPersistent: false);
            return true;
        }
    }
}
