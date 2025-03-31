using Microsoft.AspNetCore.Identity;

namespace VerifyIdentityAPI.Models
{
    public class User : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string BirthDate { get; set; }
        public ICollection<Quiz>? Quizzes { get; set; }
    }
}
