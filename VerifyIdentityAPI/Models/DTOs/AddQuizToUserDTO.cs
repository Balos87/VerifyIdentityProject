namespace VerifyIdentityAPI.Models.DTOs
{
    public class AddQuizToUserDTO
    {
        public required int QuizId{ get; set; }
        public required string Email { get; set; }
}
}
