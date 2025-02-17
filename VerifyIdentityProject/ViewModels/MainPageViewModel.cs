using System.ComponentModel;
using System.Windows.Input;
using VerifyIdentityProject.Resources.Interfaces;
using Microsoft.Maui.Controls;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls.Platform;
#if ANDROID
using Android.Widget;
using Android.App;
#endif
namespace VerifyIdentityProject
{
    public class MainPageViewModel : INotifyPropertyChanged
    {
        private readonly INfcReaderManager _nfcReaderManager;
        private string _passportData;

#if ANDROID
        private AlertDialog _nfcDialog; // Persistent Dialog
#endif

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

            _nfcReaderManager.OnNfcChipDetected += (data) =>
            {
                Console.WriteLine($"NFC Detection Event Triggered: {data}"); // Debug Log
                if (string.IsNullOrEmpty(data) || data == "NFC Reader started. Waiting for a tag...")
                {
                    Console.WriteLine("Ignored empty or initial NFC message.");
                    return; // Ignore false detections
                }

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
#if ANDROID
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
#endif
        }

        // ✅ Dismiss the dialog when NFC is detected
        private void DismissNfcDialog()
        {
#if ANDROID
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
#endif
        }

        // ✅ Method to Show Toast Messages
        private void ShowToast(string message)
        {
#if ANDROID
            var context = Platform.CurrentActivity;
            if (context != null)
            {
                context.RunOnUiThread(() =>
                {
                    Toast.MakeText(context, message, ToastLength.Short).Show();
                });
            }
#endif
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
