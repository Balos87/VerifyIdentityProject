using VerifyIdentityAPI.Models;

namespace VerifyIdentityAPI.Repositories.IRepositories
{
    public interface IQuizRepository
    {
        Task AddQuizAsync(Quiz quiz);

        Task<List<Quiz>> GetAllQuizAsync();

        Task<Quiz> FindQuizAsync(int id);

        Task AddQuizToUserAsync(UserQuiz UserQuiz);

        Task DeleteQuizAsync(int id);
    }
}
