using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using VerifyIdentityAspFrontend.Areas.Identity.Pages.Account;

namespace VerifyIdentityAspFrontend.Models
{
    public class AppRegisterModel : RegisterModel
    {
        public AppRegisterModel(UserManager<IdentityUser> userManager, IUserStore<IdentityUser> userStore, SignInManager<IdentityUser> signInManager, ILogger<RegisterModel> logger, IEmailSender emailSender) 
            : base(userManager, userStore, signInManager, logger, emailSender)
        {
        }

        public string Tibia { get; set; }
    }
}
