namespace VerifyIdentityAPI.Models
{
    public class UserQuiz
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public required User User { get; set; }
        public int QuizId { get; set; }
        public required Quiz Quiz { get; set; }
        public string? VerificationId { get; set; } // Random id will be generated for verification process between web and mobile
        public DateTime VerifIdCreatedAt { get; set; } = DateTime.UtcNow; // DateTime when the quiz was created
        public DateTime VerifIdExpiresAt { get; set; } = DateTime.UtcNow.AddMinutes(6); // DateTime when the verification id expires
        public bool isLocked { get; set; } = true; // Quiz is locked by default
        public DateTime? UnlockedAt { get; set; } = DateTime.UtcNow; // DateTime when the quiz was unlocked
        public DateTime? AccessExpiresAt { get; set; } = DateTime.UtcNow.AddHours(2); // DateTime when the quiz access expires so it wont be unlock forever
        public bool QuizIsCompleted { get; set; } = false; // Being able to complete the quiz
        public DateTime? QuizCompletedAt { get; set; } // DateTime when the quiz was completed
    }
}
