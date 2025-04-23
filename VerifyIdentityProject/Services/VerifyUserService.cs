using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Services
{
    public class VerifyUserService
    {
        private readonly HttpClient _httpClient;

        public VerifyUserService()
        {
            _httpClient = new HttpClient();
        }

        public async Task<bool> SendVerificationAsync(string firstName, string lastName, string ssn)
        {
            if (string.IsNullOrWhiteSpace(Helpers.AppState.VerifyOperationId))
                return false;

            var payload = new
            {
                token = Helpers.AppState.VerifyOperationId,
                firstName,
                lastName,
                ssn
            };

            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("https://localhost:7157/api/verify", content);
            return response.IsSuccessStatusCode;
        }
    }
}
