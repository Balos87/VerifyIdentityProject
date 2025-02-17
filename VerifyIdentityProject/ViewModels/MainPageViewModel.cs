using System.ComponentModel;
using System.Windows.Input;
using VerifyIdentityProject.Resources.Interfaces;
using Microsoft.Maui.Controls;
using Android.Widget;
using Android.App;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls.Platform;

namespace VerifyIdentityProject
{
    public class MainPageViewModel : INotifyPropertyChanged
    {
        private readonly INfcReaderManager _nfcReaderManager;
        private string _passportData;
        private AlertDialog _nfcDialog; // Persistent Dialog

        public string PassportData
        {
            get => _passportData;
            set
            {
                _passportData = value;
                OnPropertyChanged(nameof(PassportData));
            }
        }

        public ICommand StartNfcCommand { get; }
        public ICommand StopNfcCommand { get; }

        public MainPageViewModel(INfcReaderManager nfcReaderManager)
        {
            _nfcReaderManager = nfcReaderManager;

            // Subscribe to NFC detection event
            _nfcReaderManager.OnNfcChipDetected += (data) =>
            {
                PassportData = data;
                DismissNfcDialog(); // Close the "Place your device" dialog
                ShowToast("RFID Chip detected! Processing...");
            };

            StartNfcCommand = new Command(StartNfc);
            StopNfcCommand = new Command(StopNfc);
        }

        private void StartNfc()
        {
            try
            {
                _nfcReaderManager.StartListening();
                PassportData = "NFC Reader started. Waiting for a tag...";

                // ✅ Show a persistent dialog instead of a toast
                ShowNfcDialog();
            }
            catch (Exception ex)
            {
                PassportData = $"Error starting NFC: {ex.Message}";
                ShowToast($"Error: {ex.Message}");
            }
        }

        private void StopNfc()
        {
            try
            {
                _nfcReaderManager.StopListening();
                PassportData = "NFC Reader stopped.";
                DismissNfcDialog(); // Close the dialog if open
                ShowToast("NFC Scanner stopped.");
            }
            catch (Exception ex)
            {
                PassportData = $"Error stopping NFC: {ex.Message}";
                ShowToast($"Error: {ex.Message}");
            }
        }

        // ✅ Persistent Alert Dialog: "Place your device on ePassport"
        private void ShowNfcDialog()
        {
            var context = Platform.CurrentActivity;
            if (context == null) return;

            context.RunOnUiThread(() =>
            {
                AlertDialog.Builder builder = new AlertDialog.Builder(context);
                builder.SetTitle("Waiting for NFC...");
                builder.SetMessage("Place your device on ePassport");
                builder.SetCancelable(false); // Prevent user from dismissing manually

                _nfcDialog = builder.Create();
                _nfcDialog.Show();
            });
        }

        // ✅ Dismiss the dialog when NFC is detected
        private void DismissNfcDialog()
        {
            var context = Platform.CurrentActivity;
            if (context == null || _nfcDialog == null) return;

            context.RunOnUiThread(() =>
            {
                if (_nfcDialog.IsShowing)
                {
                    _nfcDialog.Dismiss();
                    _nfcDialog = null;
                }
            });
        }

        // ✅ Method to Show Toast Messages
        private void ShowToast(string message)
        {
            var context = Platform.CurrentActivity;
            if (context != null)
            {
                context.RunOnUiThread(() =>
                {
                    Toast.MakeText(context, message, ToastLength.Short).Show();
                });
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
