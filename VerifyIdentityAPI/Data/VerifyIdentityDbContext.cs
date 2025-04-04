using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using VerifyIdentityAPI.Models;

namespace VerifyIdentityAPI.Data
{
    public class VerifyIdentityDbContext : IdentityDbContext<User>
    {
        public VerifyIdentityDbContext(DbContextOptions<VerifyIdentityDbContext> options) : base(options) { }

        public DbSet<Quiz> Quizzes { get; set; }
        public DbSet<UserQuiz> UserQuizzes { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<UserQuiz>()
                .HasKey(uq => new { uq.UserId_FK, uq.QuizId_FK });

            modelBuilder.Entity<UserQuiz>()
                .HasOne(uq=>uq.User)
                .WithMany(u=>u.UserQuizzes)
                .HasForeignKey(uq=>uq.UserId_FK);

            modelBuilder.Entity<UserQuiz>()
                .HasOne(uq=>uq.Quiz)
                .WithMany(q=>q.UserQuizzes)
                .HasForeignKey(uq=>uq.QuizId_FK);
        }
    }
}
