using Microsoft.AspNetCore.Mvc;

namespace VerifyIdentityAPI.Controllers
{
    [Controller]
    public class UserController : Controller
    {
        [Route("/user")]
        public IActionResult Index()
        {
            return View();
        }
    }
}
