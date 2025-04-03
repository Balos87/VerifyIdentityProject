using Microsoft.EntityFrameworkCore;
using VerifyIdentityAPI.Data;
using VerifyIdentityAPI.Models;
using VerifyIdentityAPI.Models.DTOs;
using VerifyIdentityAPI.Repositories.IRepositories;

namespace VerifyIdentityAPI.Repositories
{
    public class QuizRepository : IQuizRepository
    {
        private readonly VerifyIdentityDbContext _context;

        public QuizRepository(VerifyIdentityDbContext context)
        {
            _context = context;
        }
        public async Task AddQuizAsync(Quiz quiz)
        {
            _context.Quizzes.Add(quiz);
            await _context.SaveChangesAsync();
            await Task.CompletedTask;
        }

        public async Task<List<Quiz>> GetAllQuizAsync()
        {
            var quiezes = await _context.Quizzes.Include(q=>q.User).ToListAsync();

            return quiezes;
        }

        public async Task<Quiz> FindQuizAsync(int quizId)
        {
            var quiz = await _context.Quizzes.Include(q=>q.User).FirstOrDefaultAsync(q=> q.Id == quizId);
            if(quiz == null)
            {
                throw new Exception("Quiz not found");
            }
            return quiz;

        }

        public async Task AddQuizToUserAsync(Quiz quiz)
        {
            _context.Quizzes.Update(new Quiz
            {
                QuizName = quiz.QuizName,
                User = quiz.User
            });
            await _context.SaveChangesAsync();
            await Task.CompletedTask;
        }

        public async Task DeleteQuizAsync(int id)
        {
            try
            {
                var quiz = await _context.Quizzes.FindAsync(id);
                if (quiz != null)
                    _context.Quizzes.Remove(quiz);
                await _context.SaveChangesAsync();
                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error removing quiz: {ex.Message}");
            }
        }
    }
}
