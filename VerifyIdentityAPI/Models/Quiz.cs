
namespace VerifyIdentityAPI.Models
{
    public class Quiz
    {
        public int Id { get; set; }
        public string? QuizName { get; set; }
        public ICollection<UserQuiz>? UserQuizzes { get; set; }
    }
}
