using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Resources.Interfaces;
using VerifyIdentityProject.Services;
using VerifyIdentityProject.ViewModels;

namespace VerifyIdentityProject
{
    public partial class MainPage : ContentPage
    {
        private MainPageViewModel _viewModel;
        private int count;
        private string? qrData = "";

        public MainPage(MainPageViewModel viewModel, INfcReaderManager nfcReaderManager)
        {
            InitializeComponent();
            var copy = new CopySecrets();
            copy.CopySecretFileToAppData();
            copy.CopyAppSettingsFileToAppData();

            _viewModel = viewModel;
            BindingContext = _viewModel;

            //for QR-code reader
            barcodeReader.Options = new ZXing.Net.Maui.BarcodeReaderOptions
            {
                Formats = ZXing.Net.Maui.BarcodeFormat.QrCode,
                AutoRotate = true,
                Multiple = true,
                TryHarder = true,
            };
        }

        private void barcodeReader_BarcodesDetected(object sender, ZXing.Net.Maui.BarcodeDetectionEventArgs e)
        {

            MainThread.BeginInvokeOnMainThread(() =>
            {
                qrData = e.Results.FirstOrDefault()?.Value;
                barcodeReader.IsVisible = false;
                barcodeReader.IsDetecting = false;
                DisplayAlert("QR data:", qrData, "OK");
            });
        }

        private void OnStartScanningClicked(object sender, EventArgs e)
        {
            barcodeReader.IsDetecting = true;
            barcodeReader.IsVisible = true;
        }
    }
}
