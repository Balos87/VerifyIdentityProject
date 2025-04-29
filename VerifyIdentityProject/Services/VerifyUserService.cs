using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using VerifyIdentityProject.Helpers;

namespace VerifyIdentityProject.Services
{
    public class VerifyUserService
    {
        private readonly HttpClient _httpClient;

        public VerifyUserService()
        {
            _httpClient = new HttpClient();

            // Fetch app settings
            var appSettings = GetSecrets.FetchAppSettings();

            // Resolve which URL to use for the ASP.NET Core backend
            Task.Run(async () =>
            {
                var selectedUrl = await APIHelper.GetAvailableUrl(appSettings?.API_URL, appSettings?.ASP_LOCAL_SERVER);
                Console.WriteLine("👉 Using backend URL: " + selectedUrl);
                _httpClient.BaseAddress = new Uri(selectedUrl);
            }).Wait();
        }

        public async Task<bool> SendVerificationAsync(string firstName, string lastName, string ssn)
        {
            if (string.IsNullOrWhiteSpace(AppState.VerifyOperationId))
                return false;

            var payload = new
            {
                operationId = AppState.VerifyOperationId,
                firstName,
                lastName,
                ssn
            };

            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync("api/verify", content);
            return response.IsSuccessStatusCode;
        }
    }
}
