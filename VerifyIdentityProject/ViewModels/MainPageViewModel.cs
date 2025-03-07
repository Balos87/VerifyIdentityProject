using System;
using System.ComponentModel;
using System.Windows.Input;
using VerifyIdentityProject.Services;
using VerifyIdentityProject.Resources.Interfaces;
using Microsoft.Maui.Controls;
using System.Text.RegularExpressions;
using VerifyIdentityProject.Helpers;

#if ANDROID
using Android.Widget;
using Android.App;
using Microsoft.Maui.ApplicationModel; // Required for Platform.CurrentActivity
#endif

namespace VerifyIdentityProject.ViewModels // Moved to ViewModels for proper organization
{
    public class MainPageViewModel : INotifyPropertyChanged
    {
        private readonly INfcReaderManager _nfcReaderManager;

        private readonly string _secretsFilePath = Path.Combine(FileSystem.AppDataDirectory, "secrets.json"); // Store in app data directory
        private readonly SecretsManager _secretsManager;

        private string _passportData;
        private string _mrzNotFound;
        private ICommand _scanMrzCommand;
        private string _manualMrz;
        private ICommand _submitManualMrzCommand;
        public ICommand SubmitManualMrzCommand =>
            _submitManualMrzCommand ??= new Command(SubmitManualMrz);


#if ANDROID
        private AlertDialog? _nfcDialog; // Nullable AlertDialog to prevent null reference errors
#endif

        public event PropertyChangedEventHandler? PropertyChanged;

        public ICommand StartNfcCommand { get; }
        public ICommand StopNfcCommand { get; }

        public ICommand ScanMrzCommand
        {
            get => _scanMrzCommand;
            set
            {
                _scanMrzCommand = value;
                OnPropertyChanged(nameof(ScanMrzCommand));
            }
        }

        public string ManualMrz
        {
            get => _manualMrz;
            set
            {
                _manualMrz = value;
                OnPropertyChanged(nameof(ManualMrz));
            }
        }

        private void SubmitManualMrz()
        {
            if (IsValidMrz(ManualMrz))
            {
                // Update UI
                PassportData = $"Manual MRZ submitted: {ManualMrz}";
                MrzNotFound = ""; // Clear error message

                // Update secrets.json
                _secretsManager.SetMrzNumbers(ManualMrz);

                // Automatically trigger NFC process
                StartNfcCommand.Execute(null);
            }
            else
            {
                MrzNotFound = "Invalid MRZ format. Please check the input.";
            }
        }


        private bool IsValidMrz(string mrz)
        {
            // PACE MRZ: Exactly 24 characters, no character restrictions
            return !string.IsNullOrWhiteSpace(mrz) && mrz.Length == 24;
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

        public string PassportData
        {
            get => _passportData;
            set
            {
                _passportData = value;
                OnPropertyChanged(nameof(PassportData));
            }
        }

        public MainPageViewModel(INfcReaderManager nfcReaderManager)
        {
            _nfcReaderManager = nfcReaderManager ?? throw new ArgumentNullException(nameof(nfcReaderManager));

            _nfcReaderManager.OnNfcChipDetected += HandleNfcChipDetected;
            _secretsManager = new SecretsManager(_secretsFilePath);
            StartNfcCommand = new Command(StartNfc);
            StopNfcCommand = new Command(StopNfc);
        }

        private void HandleNfcChipDetected(string data)
        {
            Console.WriteLine($"NFC Detection Event Triggered: {data}");

            if (string.IsNullOrEmpty(data) || data == "NFC Reader started. Waiting for a tag...")
            {
                Console.WriteLine("Ignored empty or initial NFC message.");
                return;
            }

            PassportData = data;

#if ANDROID
            DismissNfcDialog();
            ShowToast("RFID Chip detected! Processing...");
#endif
        }

        private void StartNfc()
        {
            try
            {
                _nfcReaderManager.StartListening();
                PassportData = "NFC Reader started. Waiting for a tag...";

#if ANDROID
                ShowNfcDialog();
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
        private void ShowNfcDialog()
        {
            var context = Platform.CurrentActivity;
            if (context == null) return;

            context.RunOnUiThread(() =>
            {
                if (_nfcDialog?.IsShowing == true) return;

                AlertDialog.Builder builder = new AlertDialog.Builder(context);
                builder.SetTitle("Waiting for NFC...");
                builder.SetMessage("Place your device on ePassport");
                builder.SetCancelable(false);

                _nfcDialog = builder.Create();
                _nfcDialog.Show();
            });
        }

        private void DismissNfcDialog()
        {
            var context = Platform.CurrentActivity;
            if (context == null || _nfcDialog == null) return;

            context.RunOnUiThread(() =>
            {
                if (_nfcDialog?.IsShowing == true)
                {
                    _nfcDialog.Dismiss();
                    _nfcDialog = null;
                }
            });
        }

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
#endif

        protected void OnPropertyChanged(string propertyName)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
