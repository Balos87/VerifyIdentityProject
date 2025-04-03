
namespace VerifyIdentityAPI.Models
{
    public class Quiz
    {
        public int Id { get; set; }
        public required string QuizName { get; set; }
        public ICollection<User>? User { get; set; }
    }
}
