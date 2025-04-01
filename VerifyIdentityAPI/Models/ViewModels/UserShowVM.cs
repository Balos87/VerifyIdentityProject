namespace VerifyIdentityAPI.Models.ViewModels
{
    public class UserShowVM
    {
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string BirthDate { get; set; }
        public string? PhoneNumber { get; set; }
        public ICollection<QuizShowVMUser>? Quizzes { get; set; }
    }

    public class QuizShowVMUser
    {
        public string Name { get; set; }
    }
}
