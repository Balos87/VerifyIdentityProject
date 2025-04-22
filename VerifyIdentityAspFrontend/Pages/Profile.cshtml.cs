using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Net.Codecrete.QrCodeGenerator;
using System.Security.Claims;
using System.Text;
using VerifyIdentityAspFrontend.Models.Verification;
using VerifyIdentityAspFrontend.Services;

namespace VerifyIdentityAspFrontend.Pages
{
    public class ProfileModel : PageModel
    {
        [BindProperty]
        public string Message { get; set; }
        public string UserSessionId { get; set; }//for testing
        public string SessionId { get; set; }//for testing
        public string QrCodeImageBase64 { get; set; }
        public bool IsVerified { get; set; }

        //public void OnGet()
        //{
        //    Message += $"Server time: {DateTime.Now}";
        //    UserSessionId += HttpContext.Session.GetString("UserSessionId"); //for testing
        //    SessionId += HttpContext.Session.Id; //for testing
        //}

        public void OnGet()
        {
            Message += $"Server time: {DateTime.Now}";
            UserSessionId += HttpContext.Session.GetString("UserSessionId"); //for testing
            SessionId += HttpContext.Session.Id; //for testing

            //  Fetch the verification flag
            var verified = HttpContext.Session.GetString("UserVerified");
            IsVerified = verified == "true";
        }

        //public void OnPostVerify()
        //{
        //    string sessionId = $"{{'SessionId': '{HttpContext.Session.Id}', 'Email': '{HttpContext.Session.GetString("UserSessionId")}'}}"; //fetch session id

        //    QrCode qr = QrCode.EncodeText(sessionId, QrCode.Ecc.Medium); //Creates the QR code symbol

        //    byte[] qrBytes = qr.ToPng(scale: 10, border: 2); //conver to png

        //    QrCodeImageBase64 = Convert.ToBase64String(qrBytes); //converting to base64 string

        //}

        public void OnPostVerify()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var email = User.FindFirstValue(ClaimTypes.Email)
                        ?? HttpContext.Session.GetString("UserSessionId"); // fallback if claim isn't set

            var token = Guid.NewGuid().ToString();

            VerificationStore.Verifications[token] = new PendingVerification
            {
                Token = token,
                UserId = userId,
                ExpiresAt = DateTime.UtcNow.AddMinutes(10)
            };

            var qrPayload = new
            {
                token,
                email
            };

            string json = System.Text.Json.JsonSerializer.Serialize(qrPayload);
            var qr = QrCode.EncodeText(json, QrCode.Ecc.Medium);
            var qrBytes = qr.ToPng(scale: 10, border: 2);
            QrCodeImageBase64 = Convert.ToBase64String(qrBytes);
        }


    }
}
