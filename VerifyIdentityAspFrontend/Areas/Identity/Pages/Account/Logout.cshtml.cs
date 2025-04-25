#nullable disable

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using VerifyIdentityAspFrontend.Models;

namespace VerifyIdentityAspFrontend.Areas.Identity.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;

        public LogoutModel(
            SignInManager<ApplicationUser> signInManager,
            ILogger<LogoutModel> logger)
        {
            _signInManager = signInManager;
            _logger = logger;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            // 1) Sign the user out of their Identity cookie
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");

            // 2) Clear all server‐side session data
            HttpContext.Session.Clear();

            // 3) Delete the session cookie from the browser
            //    (the default cookie name is ".AspNetCore.Session")
            Response.Cookies.Delete(".AspNetCore.Session");

            // 4) Redirect the user
            if (returnUrl != null)
            {
                return LocalRedirect(returnUrl);
            }
            else
            {
                // redirect back to the home page
                return RedirectToPage("/Index", new { area = "" });
            }
        }
    }
}
