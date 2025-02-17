using System.ComponentModel;
using System.Windows.Input;
using VerifyIdentityProject.Helpers.MRZReader;
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
        private readonly INfcReaderManager _nfcReaderManager; // ✅ Declared here
        private string _mrzNotFound;
        private ICommand _scanMrzCommand;

        public ICommand ScanMrzCommand
        {
            get => _scanMrzCommand;
            set
            {
                _scanMrzCommand = value;
                OnPropertyChanged(nameof(ScanMrzCommand)); // Notify UI
            }
        }

        public string MrzNotFound
        {
            get => _mrzNotFound;
            set
            {
                if (_mrzNotFound != value)
                {
                    _mrzNotFound = value;
                    OnPropertyChanged(nameof(MrzNotFound));
                }
            }
        }

        private string _passportData;

#if ANDROID
        private AlertDialog _nfcDialog; // ✅ Persistent Dialog (Only for Android)
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
            _nfcReaderManager = nfcReaderManager; // ✅ Now it's assigned properly

            _nfcReaderManager.OnNfcChipDetected += (data) =>
            {
                Console.WriteLine($"NFC Detection Event Triggered: {data}"); // Debug Log
                if (string.IsNullOrEmpty(data) || data == "NFC Reader started. Waiting for a tag...")
                {
                    Console.WriteLine("Ignored empty or initial NFC message.");
                    return; // Ignore false detections
                }

                PassportData = data;
#if ANDROID
                DismissNfcDialog(); // Close the "Place your device" dialog
                ShowToast("RFID Chip detected! Processing...");
#endif
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
#if ANDROID
                ShowNfcDialog(); // ✅ Show Persistent NFC Dialog (Only on Android)
#endif
            }
            catch (Exception ex)
            {
                PassportData = $"Error starting NFC: {ex.Message}";
#if ANDROID
                ShowToast($"Error: {ex.Message}");
#endif
            }
        }

        private void StopNfc()
        {
            try
            {
                _nfcReaderManager.StopListening();
                PassportData = "NFC Reader stopped.";
#if ANDROID
                DismissNfcDialog();
                ShowToast("NFC Scanner stopped.");
#endif
            }
            catch (Exception ex)
            {
                PassportData = $"Error stopping NFC: {ex.Message}";
#if ANDROID
                ShowToast($"Error: {ex.Message}");
#endif
            }
        }

#if ANDROID
        // ✅ Persistent Alert Dialog: "Place your device on ePassport"
        private void ShowNfcDialog()
        {
            var context = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
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
            var context = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
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
            var context = Microsoft.Maui.ApplicationModel.Platform.CurrentActivity;
            if (context != null)
            {
                context.RunOnUiThread(() =>
                {
                    Toast.MakeText(context, message, ToastLength.Short).Show();
                });
            }
        }
#endif

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
