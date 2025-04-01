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
                Name = addQuizDTO.Name
            });
            return Task.CompletedTask;
        }

        public async Task<List<QuizShowVM>> GetAllQuizAsync()
        {
            var quizzes = await _quizRepository.GetAllQuizAsync();
            var quizShowVMs = new List<QuizShowVM>();
            foreach (var quiz in quizzes)
            {
                quizShowVMs.Add(new QuizShowVM
                {
                    Name = quiz.Name,
                    User = quiz.User.Select(u => new UserShowVMQuiz
                    {
                        Email = u.Email,
                        FirstName = u.FirstName,
                        LastName = u.LastName,
                        BirthDate = u.BirthDate,
                        PhoneNumber = u.PhoneNumber
                    }).ToList(),
                    Id = quiz.Id
                });
            }
            return quizShowVMs;
        }


        public async Task<Quiz> FindQuizAsync(int quizId)
        {
            return await _quizRepository.FindQuizAsync(quizId);
        }

        public async Task AddQuizToUserAsync(int quizId, string userEmail)
        {
            var quiz = await _quizRepository.FindQuizAsync(quizId);
            var user = await _userRepository.FindUserByEmailAsync(userEmail);
            if (user == null || quiz == null)
            {
                throw new Exception("User or quiz not found");
            }
            else
            {
                quiz.User.Add(user);
               // await _quizRepository.AddQuizToUserAsync(quiz);
            }

            //quiz = new Quiz
            //{
            //    Name = quiz.Name,
            //    User = user //I quiz så är den en icollection men här får vi ju endast en user.
            //};
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
