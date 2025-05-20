using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using Net.Codecrete.QrCodeGenerator;
using System.Security.Claims;
using VerifyIdentityAspFrontend.Data;
using VerifyIdentityAspFrontend.Models;
using Microsoft.EntityFrameworkCore;

namespace VerifyIdentityAspFrontend.Pages
{
    public class ProfileModel : PageModel
    {
        private readonly ApplicationDbContext _db;
        public ProfileModel(ApplicationDbContext db) => _db = db;

        public string SessionId { get; private set; }
        public string? UserSessionId { get; private set; }
        public bool IsVerified { get; private set; }
        public string? QrCodeImageBase64 { get; private set; }
        public string Message { get; private set; }
        public Person PersonInfo { get; private set; }

        public void OnGet()
        {
            // 1) Lock‐in the same session every time
            SessionId = HttpContext.Session.Id;
            UserSessionId = HttpContext.Session.GetString("UserSessionId");
            Message = $"Server time: {DateTime.Now}";

            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                Message = "Ingen användare inloggad.";
                return;
            }

            var pers = _db.People.Include(p => p.User).FirstOrDefault(u => u.UserId == userId);
            if (pers == null)
            {
                Message = "Person hittades inte.";
                return;
            }
            PersonInfo = pers;

            // 2) Has any op for *this* session succeeded?
            IsVerified = _db.VerifyOperations
                .Any(v => v.SessiondId == SessionId && v.Status == Status.Success);

            // 3) If NOT verified, fetch *the latest* pending op
            if (!IsVerified)
            {
                var pending = _db.VerifyOperations
                    .Where(v => v.SessiondId == SessionId && v.Status == Status.Pending)
                    .OrderByDescending(v => v.QrCreated)
                    .FirstOrDefault();

                if (pending != null)
                {
                    var qr = QrCode.EncodeText(pending.Id.ToString(), QrCode.Ecc.Medium);
                    var png = qr.ToPng(scale: 10, border: 2);
                    QrCodeImageBase64 = Convert.ToBase64String(png);
                }
            }
        }

        public async Task<IActionResult> OnPostVerifyAsync()
        {
            HttpContext.Session.Remove("reloaded");
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var sessionId = HttpContext.Session.Id;

            // only ever one pending per session
            var pending = _db.VerifyOperations
                .Where(v => v.SessiondId == sessionId && v.Status == Status.Pending)
                .FirstOrDefault();

            if (pending == null)
            {
                _db.VerifyOperations.Add(new VerifyOperation
                {
                    Id = Guid.NewGuid(),
                    UserId = userId,
                    SessiondId = sessionId,
                    Status = Status.Pending,
                    QrCreated = DateTime.UtcNow,
                    QrExpired = DateTime.UtcNow.AddHours(10)
                });
                await _db.SaveChangesAsync();
            }

            // Post-Redirect-Get: clear the form POST 
            return RedirectToPage();
        }
    }

}
