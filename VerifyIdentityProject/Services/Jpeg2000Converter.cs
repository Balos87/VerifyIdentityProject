using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using VerifyIdentityProject.Helpers;

namespace VerifyIdentityProject.Services
{
    public class Jpeg2000Converter
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiUrl;

        public Jpeg2000Converter()
        {
            var appsettings = GetSecrets.FetchAppSettings();
            _apiUrl = GetAvailableUrl(appsettings?.API_URL, appsettings?.LOCAL_SERVER).GetAwaiter().GetResult();
            _httpClient = new HttpClient { BaseAddress = new Uri(_apiUrl) };
        }

        public async Task<byte[]> ConvertJpeg2000ToJpegAsync(byte[] imageBytes)
        {
                Console.WriteLine("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");
                Console.WriteLine("➖➖➖➖➖ConvertJpeg2000ToJpeg➖➖➖➖➖");
            try
            {
                Console.WriteLine($"Sending image to API for conversion, size: {imageBytes.Length} bytes");

                using var content = new ByteArrayContent(imageBytes);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

                // Log headers before sending the request
                //Console.WriteLine("Request Headers:");
                foreach (var header in content.Headers)
                {
                    Console.WriteLine($"{header.Key}: {string.Join(", ", header.Value)}");
                }

                var response = await _httpClient.PostAsync("api/convert/bytetojpg", content);

                Console.WriteLine($"Received API response: {response.StatusCode}");

                if (response.IsSuccessStatusCode)
                {
                    byte[] convertedBytes = await response.Content.ReadAsByteArrayAsync();
                    Console.WriteLine($"Conversion success! Converted image size: {convertedBytes.Length} bytes");
                    return convertedBytes;
                }
                else
                {
                    string errorMsg = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"Failed to convert image: {response.StatusCode} - {errorMsg}");
                    throw new Exception($"API error: {response.StatusCode} - {errorMsg}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in JPEG2000 conversion: ❌{ex.Message}❌");
                throw;
            }
        }



        private static async Task<string> GetAvailableUrl(string apiUrl, string localUrl)
        {
            if (await IsApiAvailable(apiUrl))
            {
               // Console.WriteLine($"Using API URL: {apiUrl}");
                return apiUrl;
            }

            Console.WriteLine($"API unavailable, falling back to LOCAL_SERVER: ❌{localUrl}❌");
            return localUrl ?? string.Empty;
        }

        private static async Task<bool> IsApiAvailable(string url)
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
