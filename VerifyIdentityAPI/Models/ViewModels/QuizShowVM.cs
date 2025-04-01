namespace VerifyIdentityAPI.Models.ViewModels
{
    public class QuizShowVM
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public ICollection<UserShowVMQuiz>? User { get; set; }
    }

    public class UserShowVMQuiz
    {
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string BirthDate { get; set; }
        public string PhoneNumber { get; set; }
       // public ICollection<Quiz>? Quizzes { get; set; }
    }
}
