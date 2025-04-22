using CommunityToolkit.Mvvm.Input;
using VerifyIdentityProject.ViewModels;
using ZXing.Net.Maui;

namespace VerifyIdentityProject;

public partial class QrScannerPage : ContentPage
{
    private readonly QrScannerViewModel viewModel;

    public QrScannerPage(QrScannerViewModel viewModel)
    {
        InitializeComponent();
        BindingContext = this.viewModel = viewModel;
    }

    private void OnBarcodesDetected(object sender, BarcodeDetectionEventArgs e)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            var result = e.Results.FirstOrDefault()?.Value;
            if (!string.IsNullOrWhiteSpace(result))
            {
                viewModel.ScannedValue = result;
            }
        });
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
