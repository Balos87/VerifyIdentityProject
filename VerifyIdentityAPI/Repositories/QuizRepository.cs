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
            var quiezes = await _context.Quizzes.Include(x=>x.UserQuizzes).ThenInclude(x=>x.User).ToListAsync();

            return quiezes;
        }

        public async Task<Quiz> FindQuizAsync(int quizId)
        {
            var quiz = await _context.Quizzes.Where(x=>x.Id == quizId).SingleOrDefaultAsync();
            if(quiz == null)
            {
                throw new Exception("Quiz not found");
            }
            return quiz;

        }

        public async Task AddQuizToUserAsync(UserQuiz userQuiz)
        {
            _context.UserQuizzes.Update(new UserQuiz
            {
                Quiz = userQuiz.Quiz,
                User = userQuiz.User,
            });
            await _context.SaveChangesAsync();
            await Task.CompletedTask;
        }

        public async Task DeleteQuizAsync(int id)
        {
            try
            {
                var quiz = await _context.Quizzes.Include(x=>x.UserQuizzes).ThenInclude(x=>x.Quiz.Id == id).SingleOrDefaultAsync();
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
