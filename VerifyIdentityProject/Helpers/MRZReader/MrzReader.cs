using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.Maui.Media;

namespace VerifyIdentityProject.Helpers.MRZReader
{
    public class MrzReader
    {
        private readonly HttpClient _httpClient;

        public MrzReader()
        {
            _httpClient = new HttpClient
            {
                BaseAddress = new Uri("http://192.168.50.26:5000/api/") // Local API URL
            };
        }

        public async Task ScanAndExtractMrzAsync()
        {
            try
            {
                // Capture photo using the device's camera
                var photo = await MediaPicker.CapturePhotoAsync();
                if (photo == null)
                {
                    Console.WriteLine("No photo captured.");
                    return;
                }

                // Save the photo locally
                var filePath = Path.Combine(FileSystem.CacheDirectory, photo.FileName);
                using (var stream = await photo.OpenReadAsync())
                using (var fileStream = File.OpenWrite(filePath))
                {
                    await stream.CopyToAsync(fileStream);
                }

                // Send the image to the API for MRZ extraction
                var mrzText = await ExtractMrzFromApiAsync(filePath);

                if (string.IsNullOrEmpty(mrzText))
                {
                    Console.WriteLine("No MRZ detected in the image.");
                }
                else
                {
                    Console.WriteLine($"Extracted MRZ: {mrzText}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during MRZ scan: {ex.Message}");
            }
        }

        private async Task<string> ExtractMrzFromApiAsync(string imagePath)
        {
            try
            {
                Console.WriteLine("Sending image to API...");

                // Read the image file
                byte[] imageBytes = await File.ReadAllBytesAsync(imagePath);
                var content = new MultipartFormDataContent
                {
                    { new ByteArrayContent(imageBytes), "file", Path.GetFileName(imagePath) }
                };

                // Send POST request to the API
                var response = await _httpClient.PostAsync("mrz/extract", content);

                if (response.IsSuccessStatusCode)
                {
                    var result = await response.Content.ReadFromJsonAsync<string>();
                    Console.WriteLine($"MRZ Extracted: {result}");
                    return result;
                }
                else
                {
                    Console.WriteLine($"API Error: {response.StatusCode} - {response.ReasonPhrase}");
                    return string.Empty;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error calling API: {ex.Message}");
                return string.Empty;
            }
        }
    }
}
