using System.Collections.Generic;
using Microsoft.Maui.Controls;
using VerifyIdentityProject.Services;

namespace VerifyIdentityProject
{
    [QueryProperty(nameof(DG1Data), "DG1Data")]
    [QueryProperty(nameof(ImageData), "ImageData")]
    public partial class PassportDataPage : ContentPage
    {
        private PassportDataViewModel _viewModel;

        public PassportDataPage()
        {
            InitializeComponent();
            _viewModel = new PassportDataViewModel();
            BindingContext = _viewModel;
        }

        public Dictionary<string, string> DG1Data
        {
            set
            {
                if (value != null)
                {
                    _viewModel.DG1Data = value;
                }
            }
        }

        public byte[] ImageData
        {
            set
            {
                if (value != null)
                {
                    _viewModel.ImageData = value;
                }
            }
        }
        private async void OnScanQrClicked(object sender, EventArgs e)
        {
            var qrScanner = new QrScannerService();
            var result = await qrScanner.ScanQrCodeAsync();

            if (!string.IsNullOrWhiteSpace(result))
            {
                _viewModel.ShowSendButton = true;
                await DisplayAlert("QR Scanned", "QR code was scanned and stored successfully.", "OK");
            }
            else
            {
                await DisplayAlert("Scan Cancelled", "No QR code was detected.", "OK");
            }
        }

        private async void OnSendToServerClicked(object sender, EventArgs e)
        {
            var firstName = _viewModel.DG1Data["FirstName"];
            var lastName = _viewModel.DG1Data["LastName"];
            var ssn = _viewModel.DG1Data["SSN"];

            var service = new VerifyUserService();
            var success = await service.SendVerificationAsync(firstName, lastName, ssn);

            if (success)
                await DisplayAlert("Success ", "Verification sent!", "OK");
            else
                await DisplayAlert("Error ", "Could not verify user.", "OK");
        }

    }
}