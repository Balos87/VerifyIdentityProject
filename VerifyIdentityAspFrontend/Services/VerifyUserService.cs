using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using System.Security.Claims;
using VerifyIdentityAspFrontend.Data;
using VerifyIdentityAspFrontend.Models;
using VerifyIdentityAspFrontend.Services.IServices;

namespace VerifyIdentityAspFrontend.Services
{
    public class VerifyUserService : IVerifyUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ApplicationDbContext _context;

        private readonly IMemoryCache _cache; //----------
        string sessId = "";
        public VerifyUserService(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IHttpContextAccessor httpContextAccessor, IMemoryCache cache, ApplicationDbContext context)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
            _cache = cache; //----------
            _context = context;
        }

        public async Task<bool> CheckUserDataAsync(UserDTO userDTO)
        {
            //1.check if operation exists
            var operation = await _context.Operations.SingleOrDefaultAsync(x => x.Id.ToString() == userDTO.OperationId);
            if (operation == null)
                return false;

            //2.check expireation date
            if (operation.QrExpired > DateTime.UtcNow)
                return false;

            //3.Fetch the user from the operation  
            var user = await _userManager.Users.Include(u=>u.Person).SingleOrDefaultAsync(u => u.Id == operation.UserId);

            //4.Check if the user has a person associated with them  
            if (user?.Person != null)
            {
                //5.If a person is associated, verify the incoming details against that person
                if (user.Person.FirstName == userDTO.FirstName && user.Person.LastName == userDTO.LastName && user.Person.SSN == userDTO.SSN)
                {
                    operation.Status = Status.Success;
                }
                else
                {
                    // If a person exists and the details do not match, set the status to denied.
                    operation.Status = Status.Denied;
                }
            }
            else
            {
                //6.If not, create a person and then save 
                var newPers = new Person
                {
                    FirstName = userDTO.FirstName,
                    LastName = userDTO.LastName,
                    SSN = userDTO.SSN,
                    UserId = user.Id,
                };
                _context.People.Add(newPers);

                //7.Set the status to verified  
                operation.Status = Status.Success;

            }
            await _context.SaveChangesAsync();

            return true;
        }


        //public async Task<bool> CheckUserDataAsync(UserDTO userDTO)
        //{
        //    var user = await _userManager.FindByEmailAsync(userDTO.Email);
        //    if (user == null)
        //    {
        //        throw new Exception($"couldn't find user with email: {userDTO.Email}");
        //    }
        //    string cacheKey = $"verification_{userDTO.Email}"; //----------
        //    if (_cache.TryGetValue(cacheKey, out string storedSessionId)) //----------
        //    {
        //        sessId = storedSessionId; //----------
        //    }

        //    if (sessId != userDTO.SessionId)
        //    {
        //        throw new Exception($"SessionId didnt match. Incoming-id:{userDTO.SessionId} Stored-id: {sessId}");
        //    }
        //    var claims = new List<Claim>
        //    {
        //        new Claim("FirstName", userDTO.FirstName),
        //        new Claim("LastName", userDTO.LastName),
        //        new Claim("SSN", userDTO.SSN)
        //    };

        //    var result = await _userManager.AddClaimsAsync(user, claims);
        //    if (!result.Succeeded) return false;

        //    //login the user again so the claims gets into the session
        //    await _signInManager.SignInAsync(user, isPersistent: false);
        //    return true;
        //}
    }
}
