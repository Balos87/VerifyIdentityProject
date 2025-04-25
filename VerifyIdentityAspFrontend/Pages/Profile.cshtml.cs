using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using Net.Codecrete.QrCodeGenerator;
using System.Text;
using VerifyIdentityAspFrontend.Data;
using VerifyIdentityAspFrontend.Models;

namespace VerifyIdentityAspFrontend.Pages
{
    public class ProfileModel : PageModel
    {
        [BindProperty]
        public string Message { get; set; }
        public string UserEmail { get; set; }//for testing
        public string UserSessionId { get; set; }//for testing
        public string SessionId { get; set; }//for testing
        public string QrCodeImageBase64 { get; set; }
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _dbContext;

        private readonly IMemoryCache _cache;  //----------

        public ProfileModel(IMemoryCache cache, UserManager<ApplicationUser> userManager, ApplicationDbContext dbContext)  //----------
        {
            _cache = cache; //----------
            _userManager = userManager;
            _dbContext = dbContext;

        }
        public void OnGet()
        {
            Message += $"Server time: {DateTime.Now}";
            UserEmail += HttpContext.Session.GetString("UserEmail"); //for testing
            UserSessionId += HttpContext.Session.GetString("UserSessionId"); //for testing
            SessionId += HttpContext.Session.Id; //for testing

            string cacheKey = $"verification_{UserEmail}"; //----------

            _cache.Set(cacheKey, SessionId, TimeSpan.FromMinutes(10)); //----------
        }

        public async Task<IActionResult> OnPostVerify()
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
            {
                // Handle the case where the email is null or empty  
                throw new ArgumentException("User email is not available in the session.");
            }

            var user = await _userManager.FindByEmailAsync(userEmail);
            if (user == null)
            {
                throw new Exception("User not found.");
            }

            var operation = new VerifyOperation
            {
                UserId = user.Id,
                SessiondId = HttpContext.Session.Id,
            };
            _dbContext.Operations.Add(operation);
            await _dbContext.SaveChangesAsync();

            var operationId = operation.Id.ToString();

            QrCode qr = QrCode.EncodeText(operationId, QrCode.Ecc.Medium); // Creates the QR code symbol  

            byte[] qrBytes = qr.ToPng(scale: 10, border: 2); // Convert to PNG  

            QrCodeImageBase64 = Convert.ToBase64String(qrBytes); // Convert to Base64 string  

            return Page();
        }
    }
}
