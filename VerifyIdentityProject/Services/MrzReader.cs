using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Microsoft.Maui.Media;
using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Resources.Interfaces;
using VerifyIdentityProject.ViewModels;
using VerifyIdentityProject.Helpers.Exceptions;

namespace VerifyIdentityProject.Services
{
    public class MrzReader
    {
        private readonly Action<string> _mrzNotFoundCallback;
        private readonly HttpClient _httpClient;
        private readonly INfcReaderManager _nfcReaderManager;
        private bool _nfcTagLost;

        public MrzReader(Action<string> mrzNotFoundCallback, INfcReaderManager nfcReaderManager)
        {
            var appsettings = GetSecrets.FetchAppSettings();

            _nfcReaderManager = nfcReaderManager;
            _mrzNotFoundCallback = mrzNotFoundCallback;
            _httpClient = new HttpClient();

            // Subscribe to NFC tag lost event
            _nfcReaderManager.OnNfcTagLost += HandleNfcTagLost;

            Task.Run(async () =>
            {
                var selectedUrl = await APIHelper.GetAvailableUrl(appsettings?.API_URL, appsettings?.LOCAL_SERVER);
                _httpClient.BaseAddress = new Uri(selectedUrl);
            }).Wait();
        }

        public async Task ScanAndExtractMrzAsync()
        {
            Console.WriteLine("➖➖➖➖➖ ScanAndExtractMrzAsync Started ➖➖➖➖➖");
            _nfcTagLost = false;

            try
            {
                var photo = await MediaPicker.CapturePhotoAsync();
                if (photo == null)
                {
                    Console.WriteLine("No photo captured.");
                    return;
                }

                _mrzNotFoundCallback?.Invoke(MauiStatusMessageHelper.MrzProcessingMessage);
                Console.WriteLine(MauiStatusMessageHelper.MrzProcessingMessage);

                var filePath = Path.Combine(FileSystem.CacheDirectory, photo.FileName);
                using (var stream = await photo.OpenReadAsync())
                using (var fileStream = File.OpenWrite(filePath))
                {
                    await stream.CopyToAsync(fileStream);
                }

                var mrzText = await ExtractMrzFromApiAsync(filePath);
                CheckForMrzAndNotify(mrzText);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during MRZ scan: {ex.Message}");
                _mrzNotFoundCallback?.Invoke(string.Format(MauiStatusMessageHelper.MrzScanningErrorMessage, ex.Message));
            }
        }

        private async void CheckForMrzAndNotify(string mrzText)
        {
            if (string.IsNullOrEmpty(mrzText))
            {
                Console.WriteLine(MauiStatusMessageHelper.MrzNotDetectedMessage);
                _mrzNotFoundCallback?.Invoke(MauiStatusMessageHelper.MrzNotDetectedMessage);
            }
            else
            {
                Console.WriteLine(string.Format(MauiStatusMessageHelper.MrzExtractedMessage, mrzText));

                _mrzNotFoundCallback?.Invoke($"MRZ:{mrzText}");

                string secretsFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "secrets.json");
                SecretsManager manager = new SecretsManager(secretsFilePath);
                manager.SetMrzNumbers(mrzText);

                await Task.Delay(5000);

                _mrzNotFoundCallback?.Invoke(MauiStatusMessageHelper.NfcReaderStartedMessage);
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
                    Headers = { ContentType = new MediaTypeHeaderValue("image/jpeg") }
                };

                content.Add(fileContent, "file", Path.GetFileName(imagePath));

                var responseTask = _httpClient.PostAsync("api/mrz/extract", content);

                var response = await responseTask;
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

        /// <summary>
        /// Handles NFC tag lost event.
        /// </summary>
        private void HandleNfcTagLost(string message)
        {
            _nfcTagLost = true;
            Console.WriteLine(message);
            _mrzNotFoundCallback?.Invoke(message);
        }
    }
}
