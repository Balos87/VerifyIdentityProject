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

        Task AddQuizToUserAsync(AddQuizToUserDTO addQuizToUserDTO);

        Task DeleteQuizAsync(int id);
    }
}
