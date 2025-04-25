using CommunityToolkit.Mvvm.Input;
using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Resources.Interfaces;
using VerifyIdentityProject.ViewModels;
using ZXing.Net.Maui;

namespace VerifyIdentityProject;

public partial class QrScannerPage : ContentPage
{
    private readonly QrScannerViewModel viewModel;
    private bool _hasScanned = false;
    private readonly INfcReaderManager nfcReaderManager;


    public QrScannerPage(QrScannerViewModel viewModel, INfcReaderManager nfcReaderManager)
    {
        InitializeComponent();
        this.nfcReaderManager = nfcReaderManager;
        BindingContext = this.viewModel = viewModel;
    }
    protected override async void OnAppearing()
    {
        base.OnAppearing();


        await Task.Delay(300); // give system a breath to recover from previous page
        Console.WriteLine(" QrScannerPage OnAppearing");
        nfcReaderManager.StopListening(); // just to be safe
        nfcReaderManager.StartListening(); // re-init NFC

        //// Reset scanner state in case the user returns to this page
        //_hasScanned = false;
        cameraView.IsDetecting = true;
    }
    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        Console.WriteLine(" QrScannerPage OnDisappearing");

        cameraView.IsDetecting = false; // Disable camera detection
        cameraView.IsVisible = false; // Optional: hide camera view if it helps


        if (cameraView.Parent is Layout layout)
        {
            layout.Children.Remove(cameraView);
            Console.WriteLine(" CameraView removed from layout");
        }

        nfcReaderManager.StopListening(); // Clean up NFC
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

            //  Set flag before navigating back
            AppState.ShouldRestartNfc = true;

            // Navigate to MainPage
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                await Task.Delay(200);
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
