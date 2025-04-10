using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Net.Codecrete.QrCodeGenerator;
using System.Text;

namespace VerifyIdentityAspFrontend.Pages
{
    public class ProfileModel : PageModel
    {
        [BindProperty]
        public string Message { get; set; }
        public string UserSessionId { get; set; }//for testing
        public string SessionId { get; set; }//for testing
        public string QrCodeImageBase64 { get; set; }
        public void OnGet()
        {
            Message += $"Server time: {DateTime.Now}";
            UserSessionId += HttpContext.Session.GetString("UserSessionId"); //for testing
            SessionId += HttpContext.Session.Id; //for testing
        }

        public void OnPostVerify()
        {
            string sessionId = HttpContext.Session.Id; //fetch session id

            QrCode qr = QrCode.EncodeText(sessionId, QrCode.Ecc.Medium); //Creates the QR code symbol

            byte[] qrBytes = qr.ToPng(scale: 10, border: 2); //conver to png

            QrCodeImageBase64 = Convert.ToBase64String(qrBytes); //converting to base64 string

        }
    }
}
