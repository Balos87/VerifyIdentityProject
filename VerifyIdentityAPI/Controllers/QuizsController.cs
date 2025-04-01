using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using VerifyIdentityAPI.Data;
using VerifyIdentityAPI.Models;
using VerifyIdentityAPI.Models.DTOs;
using VerifyIdentityAPI.Models.ViewModels;
using VerifyIdentityAPI.Services.IServices;

namespace VerifyIdentityAPI.Controllers
{
    public class QuizsController : Controller
    {
        private readonly IQuizService _quizService;

        public QuizsController(IQuizService quizService)
        {
            _quizService = quizService;
        }

        [HttpPost]
        [Route("/quiz/add")]
        public async Task<IActionResult> AddQuiz([FromBody] AddQuizDTO addQuizDTO)
        {
            try
            {
                await _quizService.AddQuizAsync(addQuizDTO);
                return Ok("Quiz added");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet]
        [Route("/quiz/all")]
        public async Task<ActionResult<List<QuizShowVM>>> GetAllQuiz()
        {
            try
            {
                var quizzes = await _quizService.GetAllQuizAsync();
                return Ok(quizzes);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet]
        [Route("/quiz/{quizId}")]
        public async Task<ActionResult<Quiz>> FindQuiz(int quizId)
        {
            try
            {
                var quiz = await _quizService.FindQuizAsync(quizId);
                return Ok(quiz);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost]
        [Route("/quiz/addToUser")]
        public async Task<IActionResult> AddQuizToUser([FromBody] AddQuizToUserDTO addQuizToUserDTO)
        {
            try
            {
                await _quizService.AddQuizToUserAsync(addQuizToUserDTO.QuizId, addQuizToUserDTO.Email);
                return Ok("Quiz added to user");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
