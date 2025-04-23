using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Net.Codecrete.QrCodeGenerator;
using System.Security.Claims;
using System.Text;
using VerifyIdentityAspFrontend.Data;
using VerifyIdentityAspFrontend.Models;
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
        private readonly ApplicationDbContext _db;

        public ProfileModel(ApplicationDbContext db)
        {
            _db = db;
        }

        //public void OnGet()
        //{
        //    Message += $"Server time: {DateTime.Now}";
        //    UserSessionId += HttpContext.Session.GetString("UserSessionId"); //for testing
        //    SessionId += HttpContext.Session.Id; //for testing
        //}

        public void OnGet()
        {
            SessionId = HttpContext.Session.Id;

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

        public async Task<IActionResult> OnPostVerifyAsync()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var sessionId = HttpContext.Session.Id;

            // Create and save the operation in DB
            var operation = new VerifyOperation
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                SessiondId = sessionId,
                QrCreated = DateTime.UtcNow,
                QrExpired = DateTime.UtcNow.AddMinutes(10),
                Status = Status.Pending
            };

            _db.VerifyOperations.Add(operation);
            await _db.SaveChangesAsync();

            // Generate QR Code from the operation Id
            string idToEncode = operation.Id.ToString();
            var qr = QrCode.EncodeText(idToEncode, QrCode.Ecc.Medium);
            var qrBytes = qr.ToPng(scale: 10, border: 2);
            QrCodeImageBase64 = Convert.ToBase64String(qrBytes);

            return Page(); // Return to same page and display QR
        }



    }
}
