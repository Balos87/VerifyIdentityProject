using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using Net.Codecrete.QrCodeGenerator;
using System.Text;

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

        private readonly IMemoryCache _cache;  //----------

        public ProfileModel(IMemoryCache cache)  //----------
        {
            _cache = cache; //----------
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

        public void OnPostVerify()
        {
            string sessionId = $"{{'SessionId': '{HttpContext.Session.Id}', 'Email': '{HttpContext.Session.GetString("UserEmail")}'}}"; //fetch session id

            QrCode qr = QrCode.EncodeText(sessionId, QrCode.Ecc.Medium); //Creates the QR code symbol

            byte[] qrBytes = qr.ToPng(scale: 10, border: 2); //conver to png

            QrCodeImageBase64 = Convert.ToBase64String(qrBytes); //converting to base64 string

        }
    }
}
