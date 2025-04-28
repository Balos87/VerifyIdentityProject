using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Maui.Controls;

namespace VerifyIdentityProject.ViewModels
{
    public partial class QrScannerViewModel : ObservableObject
    {
        [ObservableProperty]
        private string scannedValue;

        [RelayCommand]
        private async Task Capture()
        {
            if (!string.IsNullOrWhiteSpace(ScannedValue))
            {
                await Application.Current.MainPage.DisplayAlert("Captured", $"QR Code: {ScannedValue}", "OK");

                // Optionally stop scanning or navigate:
                // await Shell.Current.GoToAsync("..");
            }
            else
            {
                await Application.Current.MainPage.DisplayAlert("No QR code", "No code has been detected yet. Try again.", "OK");
            }
        }
    }
}
