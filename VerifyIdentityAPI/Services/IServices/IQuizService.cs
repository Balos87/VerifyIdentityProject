using VerifyIdentityAPI.Models;
using VerifyIdentityAPI.Models.DTOs;
using VerifyIdentityAPI.Models.ViewModels;

namespace VerifyIdentityAPI.Services.IServices
{
    public interface IQuizService
    {
        Task AddQuizAsync(AddQuizDTO addQuizDTO);

        Task<List<QuizShowVM>> GetAllQuizAsync();

        Task<Quiz> FindQuizAsync(int quizId);

        Task AddQuizToUserAsync(int quizId, string userEmail);

        Task DeleteQuizAsync(int id);
    }
}
