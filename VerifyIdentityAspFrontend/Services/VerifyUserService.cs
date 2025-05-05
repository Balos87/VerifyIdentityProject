using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
        private readonly ApplicationDbContext _db;

        public VerifyUserService(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IHttpContextAccessor httpContextAccessor,
            ApplicationDbContext db)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _httpContextAccessor = httpContextAccessor;
            _db = db;
        }

        public async Task<Status> ProcessVerificationAsync(
            Guid operationId,
            string firstName,
            string lastName,
            string ssn)
        {
            // 1) Fetch the VerifyOperation + its linked user
            var verifyOp = await _db.VerifyOperations
                                    .Include(v => v.User)
                                        .ThenInclude(u => u.Person)
                                    .FirstOrDefaultAsync(v => v.Id == operationId);
            if (verifyOp == null)
                return Status.Denied;

            var user = verifyOp.User!;

            // 2) GLOBAL SSN CHECK: does that SSN already exist in any Person record?
            var other = await _db.People
                                 .AsNoTracking()
                                 .FirstOrDefaultAsync(p => p.SSN == ssn);
            if (other != null && other.UserId != user.Id)
            {
                // someone else already claimed this SSN
                verifyOp.Status = Status.Denied;

                // persist and bail
                _db.VerifyOperations.Update(verifyOp);
                await _db.SaveChangesAsync();
                return Status.Denied;
            }

            // 3) Now it’s safe to either create or compare on *this* user
            if (user.Person is null)
            {
                // no person yet on this user → create it
                var newPerson = new Person
                {
                    FirstName = firstName,
                    LastName = lastName,
                    SSN = ssn,
                    UserId = user.Id
                };
                _db.People.Add(newPerson);
                verifyOp.Status = Status.Success;
            }
            else if (user.Person.FirstName == firstName
                  && user.Person.LastName == lastName
                  && user.Person.SSN == ssn)
            {
                // the user’s person matches exactly
                verifyOp.Status = Status.Success;
            }
            else
            {
                // user has a person but the data doesn’t line up
                verifyOp.Status = Status.Denied;
            }

            // 4) Save everything
            _db.VerifyOperations.Update(verifyOp);
            await _db.SaveChangesAsync();

            // 5) (Optional) set session flags, log, etc.
            var ok = verifyOp.Status == Status.Success;
            var session = _httpContextAccessor.HttpContext?.Session;
            session?.SetString("UserVerified", ok ? "true" : "false");
            session?.SetString("VerificationStatus", verifyOp.Status.ToString().ToLower());
            Console.WriteLine($"✅ User {user.Email} verification: {verifyOp.Status}");

            return verifyOp.Status;
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

            var currentSessionId = _httpContextAccessor.HttpContext?.Session.Id;
            var emailInSession = _httpContextAccessor.HttpContext?.Session.GetString("UserSessionId");

            Console.WriteLine($"Current server-side SessionId: {currentSessionId}");
            Console.WriteLine($"Stored Email in session: {emailInSession}");
            Console.WriteLine($"Incoming SessionId: {userDTO.SessionId}");
            Console.WriteLine($"Incoming Email: {userDTO.Email}");

            var result = await _userManager.AddClaimsAsync(user, claims);
            if (!result.Succeeded) return false;

            await _signInManager.SignInAsync(user, isPersistent: false);
            return true;
        }
    }
}