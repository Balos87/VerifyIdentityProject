using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Logging;
using VerifyIdentityAspFrontend.Areas.Identity.Pages.Account;
using VerifyIdentityAspFrontend.Models;

namespace VerifyIdentityAspFrontend.Models
{
    public class AppRegisterModel : RegisterModel
    {
        public AppRegisterModel(
            UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore,
            SignInManager<ApplicationUser> signInManager,
            ILogger<RegisterModel> logger,
            IEmailSender emailSender)
            : base(userManager, userStore, signInManager, logger, emailSender)
        {
        }

        public string Tibia { get; set; }
    }
}
