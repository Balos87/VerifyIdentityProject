﻿using System;
using System.Buffers.Text;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Maui.Media;
using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Resources.Interfaces;

namespace VerifyIdentityProject.Helpers.MRZReader
{
    public class MrzReader
    {
        private readonly Action<string> _mrzNotFoundCallback;
        private readonly HttpClient _httpClient;
        private readonly INfcReaderManager _nfcReaderManager;
        public MrzReader(Action<string> mrzNotFoundCallback, INfcReaderManager nfcReaderManager)
        {
            var appsettings = GetSecrets.FetchAppSettings();

            _nfcReaderManager = nfcReaderManager;
            _mrzNotFoundCallback = mrzNotFoundCallback; // Store the callback
            _httpClient = new HttpClient();

            Task.Run(async () =>
            {
                var selectedUrl = await GetAvailableUrl(appsettings?.API_URL, appsettings?.LOCAL_SERVER);
                _httpClient.BaseAddress = new Uri(selectedUrl);
            }).Wait(); // Ensures BaseAddress is set before proceeding

        }

        private static async Task<string> GetAvailableUrl(string apiUrl, string localUrl)
        {
            if (await IsApiAvailable(apiUrl))
            {
                Console.WriteLine($"Using API URL: {apiUrl}");
                return apiUrl;
            }

            Console.WriteLine($"API unavailable, falling back to LOCAL_SERVER: {localUrl}");
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
                _mrzNotFoundCallback?.Invoke("The image is being processed, please wait...");
                // Save the photo locally
                var filePath = Path.Combine(FileSystem.CacheDirectory, photo.FileName);
                using (var stream = await photo.OpenReadAsync())
                using (var fileStream = File.OpenWrite(filePath))
                {
                    await stream.CopyToAsync(fileStream);
                }

                // Send the cropped MRZ region to the API
                var mrzText = await ExtractMrzFromApiAsync(filePath);

                // Check for MRZ and notify
                CheckForMrzAndNotify(mrzText);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during MRZ scan: {ex.Message}");
            }
        }

        // The method that checks MRZ and triggers the callback
        private void CheckForMrzAndNotify(string mrzText)
        {
            if (string.IsNullOrEmpty(mrzText))
            {
                Console.WriteLine("No MRZ detected in the image.");
                _mrzNotFoundCallback?.Invoke("No MRZ detected in the image.");
            }
            else
            {
                // Define the path to your secrets.json file.
                string secretsFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "secrets.json");

                // Create an instance of the SecretsManager.
                SecretsManager manager = new SecretsManager(secretsFilePath);

                // Update the MRZ_NUMBERS value.
                manager.SetMrzNumbers(mrzText);
                // Clear message if MRZ is found
                _mrzNotFoundCallback?.Invoke("Place your phone on passport."); // Clear message
                _nfcReaderManager.StartListening();
            }
        }

        private async Task<string> ExtractMrzFromApiAsync(string imagePath)
        {
            try
            {
                Console.WriteLine("Sending image to API...");

                using var fileStream = File.OpenRead(imagePath);
                using var content = new MultipartFormDataContent();

                var fileContent = new StreamContent(fileStream)
                {
                    Headers =
                    {
                        ContentType = new MediaTypeHeaderValue("image/jpeg")
                    }
                };

                content.Add(fileContent, "file", Path.GetFileName(imagePath));

                var response = await _httpClient.PostAsync("api/mrz/extract", content);

                var responseString = await response.Content.ReadFromJsonAsync<string>();

                if (response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"MRZ Extracted: {responseString}");
                    return responseString;
                }
                else
                {
                    Console.WriteLine($"API Error: {response.StatusCode} - {responseString}");
                    return string.Empty;
                }
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"HTTP Request error: {ex.Message}");
                return string.Empty;
            }
        }
    }
}

