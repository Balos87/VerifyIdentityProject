using Microsoft.AspNetCore.Mvc;
using System.IO;
using System.Threading.Tasks;
using VerifyIdentityAPI.Services;

namespace VerifyIdentityAPI.Controllers
{
    [ApiController]
    [Route("api/mrz")]
    public class MrzController : ControllerBase
    {
        private readonly IMrzService _mrzService;

        public MrzController(IMrzService mrzService)
        {
            _mrzService = mrzService;
        }

        [HttpPost("extract")]
        public async Task<IActionResult> ExtractMrz(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest("No file uploaded.");

            try
            {
                // Save the file temporarily
                var tempFilePath = Path.GetTempFileName();
                await using (var stream = new FileStream(tempFilePath, FileMode.Create))
                {
                    await file.CopyToAsync(stream);
                }

                // Process the file to extract MRZ
                var mrzText = await _mrzService.ExtractMrzAsync(tempFilePath);

                // Delete the temporary file
                System.IO.File.Delete(tempFilePath);

                return Ok(mrzText);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error processing MRZ: {ex.Message}");
            }
        }
    }
}

