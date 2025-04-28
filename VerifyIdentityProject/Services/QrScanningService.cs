using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;
using ZXing.Net.Maui;
using ZXing.Net.Maui.Controls;
using VerifyIdentityProject.Helpers;

namespace VerifyIdentityProject.Services
{
    public class QrScannerService
    {
        public async Task<string> ScanQrCodeAsync()
        {
            var scanResultSource = new TaskCompletionSource<string>();

            // Create camera view for scanning
            var cameraView = new CameraBarcodeReaderView
            {
                IsDetecting = true,
                HorizontalOptions = LayoutOptions.Fill,
                VerticalOptions = LayoutOptions.Fill
            };

            void OnBarcodesDetected(object sender, BarcodeDetectionEventArgs e)
            {
                var result = e.Results.FirstOrDefault()?.Value;
                if (!string.IsNullOrWhiteSpace(result) && !scanResultSource.Task.IsCompleted)
                {
                    Console.WriteLine($"✅ QR Code Detected: {result}");
                    AppState.VerifyOperationId = result;
                    scanResultSource.TrySetResult(result);
                    cameraView.BarcodesDetected -= OnBarcodesDetected;
                    cameraView.IsDetecting = false;
                }
            }

            cameraView.BarcodesDetected += OnBarcodesDetected;

            var scannerPage = new ContentPage
            {
                Content = cameraView
            };

            var navigation = Application.Current.MainPage?.Navigation;
            if (navigation == null)
            {
                return null;
            }

            await navigation.PushModalAsync(scannerPage);

            var scannedValue = await scanResultSource.Task;

            cameraView.IsDetecting = false;
            cameraView.BarcodesDetected -= OnBarcodesDetected;
            await Task.Delay(100); // Give camera time to shut down cleanly
            await navigation.PopModalAsync();

            return scannedValue;
        }
    }
}
