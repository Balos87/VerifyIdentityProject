using CommunityToolkit.Mvvm.Input;
using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.ViewModels;
using ZXing.Net.Maui;

namespace VerifyIdentityProject;

public partial class QrScannerPage : ContentPage
{
    private readonly QrScannerViewModel viewModel;
    private bool _hasScanned = false;


    public QrScannerPage(QrScannerViewModel viewModel)
    {
        InitializeComponent();
        BindingContext = this.viewModel = viewModel;
    }
    protected override void OnAppearing()
    {
        base.OnAppearing();

        // Reset scanner state in case the user returns to this page
        _hasScanned = false;
        cameraView.IsDetecting = true;
    }

    private void OnBarcodesDetected(object sender, BarcodeDetectionEventArgs e)
    {
        if (_hasScanned) return; // prevent re-entry

        var result = e.Results.FirstOrDefault()?.Value;

        if (!string.IsNullOrWhiteSpace(result))
        {
            _hasScanned = true; // lock it after scan

            Console.WriteLine($" QR Scan result: {result}");

            // Store the scanned ID globally
            AppState.VerifyOperationId = result;

            // Stop detecting further
            cameraView.IsDetecting = false;

            // Navigate to MainPage
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                await Shell.Current.GoToAsync("//MainPage");
            });
        }
    }



    [RelayCommand]
    private async Task Capture()
    {
        Console.WriteLine($"[QR] Capture tapped. Value: {viewModel.ScannedValue}");

        if (!string.IsNullOrWhiteSpace(viewModel.ScannedValue))
        {
            await Application.Current.MainPage.DisplayAlert("Captured", $"QR Code: {viewModel.ScannedValue}", "OK");
        }
        else
        {
            await Application.Current.MainPage.DisplayAlert("No QR code", "No code has been detected yet. Try again.", "OK");
        }

    }

}
