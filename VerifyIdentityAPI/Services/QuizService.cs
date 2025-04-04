using VerifyIdentityAPI.Models;
using VerifyIdentityAPI.Models.DTOs;
using VerifyIdentityAPI.Models.ViewModels;
using VerifyIdentityAPI.Repositories.IRepositories;
using VerifyIdentityAPI.Services.IServices;

namespace VerifyIdentityAPI.Services
{
    public class QuizService : IQuizService
    {
        private readonly IQuizRepository _quizRepository;
        private readonly IUserRepository _userRepository;
        public QuizService(IQuizRepository quizRepository, IUserRepository userRepository)
        {
            _quizRepository = quizRepository;
            _userRepository = userRepository;
        }

        public Task AddQuizAsync(AddQuizDTO addQuizDTO)
        {
            _quizRepository.AddQuizAsync(new Quiz
            {
                QuizName = addQuizDTO.Name
            });
            return Task.CompletedTask;
        }

        public async Task<List<QuizShowVM>> GetAllQuizAsync()
        {
            var quizzes = await _quizRepository.GetAllQuizAsync();
            var quizShowVMs = new List<QuizShowVM>();

            foreach (var quiz in quizzes)
            {
                var ngt = quiz.UserQuizzes.Select(x => x.User).SingleOrDefault();
                quizShowVMs.Add(new QuizShowVM
                {
                    Id = quiz.Id,
                    Name = quiz.QuizName,
                    User = quiz.UserQuizzes.Select(x => x.User).Select(x => new UserShowVMQuiz
                    {
                        Email = x.Email,
                        FirstName = x.FirstName,
                        LastName = x.LastName,
                        BirthDate = x.BirthDate,
                        PhoneNumber = x.PhoneNumber
                    }).ToList()
                });
            }
            return quizShowVMs;
        }


        public async Task<Quiz> FindQuizAsync(int quizId)
        {
            return await _quizRepository.FindQuizAsync(quizId);
        }

        public async Task AddQuizToUserAsync(AddQuizToUserDTO addQuizToUserDTO)
        {
            var quiz = await _quizRepository.FindQuizAsync(addQuizToUserDTO.QuizId);
            var user = await _userRepository.FindUserByEmailAsync(addQuizToUserDTO.Email);
            if (user == null || quiz == null)
            {
                throw new Exception("User or quiz not found");
            }
            else
            {
                var userQuiz = new UserQuiz { User = user, Quiz = quiz };
                await _quizRepository.AddQuizToUserAsync(userQuiz);
            }

        }

        public async Task DeleteQuizAsync(int quizId)
        {
            var quiz = await _quizRepository.FindQuizAsync(quizId);
            if(quiz != null)
            {
                await _quizRepository.DeleteQuizAsync(quizId);
            }
            else
            {
                throw new Exception("Quiz not found");
            }
        }
    }
}
