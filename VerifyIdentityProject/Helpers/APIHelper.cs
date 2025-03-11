using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    class APIHelper
    {
        public static async Task<string> GetAvailableUrl(string apiUrl, string localUrl)
        {
            if (await IsApiAvailable(apiUrl))
            {
               // Console.WriteLine($"Using API URL: {apiUrl}");
                return apiUrl;
            }

            Console.WriteLine($"API unavailable, falling back to LOCAL_SERVER: {localUrl}");
            return localUrl ?? string.Empty;
        }

        public static async Task<bool> IsApiAvailable(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return false;
            }

            string healthCheckUrl = $"{url}api/health";

            try
            {
                using var httpClient = new HttpClient();
                var response = await httpClient.GetAsync(healthCheckUrl);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }
}
