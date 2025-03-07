using System;
using System.ComponentModel;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Maui.ApplicationModel;
using Microsoft.Maui.Controls;
using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Resources.Interfaces;
using VerifyIdentityProject.Services;

#if ANDROID
using Android.Widget;
#endif

namespace VerifyIdentityProject.ViewModels
{
    public class MainPageViewModel : INotifyPropertyChanged
    {
        private readonly INfcReaderManager _nfcReaderManager;
        private readonly SecretsManager _secretsManager;
        private readonly string _secretsFilePath = Path.Combine(FileSystem.AppDataDirectory, "secrets.json");

        private string _passportData;
        private string _mrzNotFound;
        private string _manualMrz;
        private bool _isScanning;

        public event PropertyChangedEventHandler? PropertyChanged;

        public ICommand StartNfcCommand { get; }
        public ICommand StopNfcCommand { get; }
        public ICommand SubmitManualMrzCommand { get; }
        public ICommand ScanMrzCommand { get; set; }

        public string ManualMrz
        {
            get => _manualMrz;
            set
            {
                if (_manualMrz != value)
                {
                    _manualMrz = value;
                    OnPropertyChanged(nameof(ManualMrz));
                }
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

        public string PassportData
        {
            get => _passportData;
            set
            {
                if (_passportData != value)
                {
                    _passportData = value;
                    OnPropertyChanged(nameof(PassportData));
                }
            }
        }

        public bool IsScanning
        {
            get => _isScanning;
            set
            {
                if (_isScanning != value)
                {
                    _isScanning = value;
                    OnPropertyChanged(nameof(IsScanning));
                }
            }
        }

        public MainPageViewModel(INfcReaderManager nfcReaderManager)
        {
            _nfcReaderManager = nfcReaderManager ?? throw new ArgumentNullException(nameof(nfcReaderManager));

            // Prevent multiple event subscriptions
            _nfcReaderManager.OnNfcChipDetected -= HandleNfcChipDetected;
            _nfcReaderManager.OnNfcChipDetected += HandleNfcChipDetected;

            _nfcReaderManager.OnNfcTagDetected -= HandleNfcTagDetected;
            _nfcReaderManager.OnNfcTagDetected += HandleNfcTagDetected;

            _nfcReaderManager.OnNfcProcessingStarted -= HandleNfcProcessingStarted;
            _nfcReaderManager.OnNfcProcessingStarted += HandleNfcProcessingStarted;

            _nfcReaderManager.OnNfcProcessingCompleted -= HandleNfcProcessingCompleted;
            _nfcReaderManager.OnNfcProcessingCompleted += HandleNfcProcessingCompleted;

            _secretsManager = new SecretsManager(_secretsFilePath);
            StartNfcCommand = new Command(StartNfc);
            StopNfcCommand = new Command(StopNfc);
            SubmitManualMrzCommand = new Command(SubmitManualMrz);
            ScanMrzCommand = new Command(async () => await ScanMrzAsync());
        }

        private void HandleNfcChipDetected(string message)
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                PassportData = message;
            });
        }

        private void HandleNfcTagDetected(string message)
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                PassportData = message;
            });
        }

        private void HandleNfcProcessingStarted(string message)
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                PassportData = message;
                IsScanning = true;
            });
        }

        private void HandleNfcProcessingCompleted(string message)
        {
            MainThread.BeginInvokeOnMainThread(async () =>
            {
                PassportData = message;
                await Task.Delay(2000); // Delay before showing final data
                IsScanning = false;
            });
        }

        private void SubmitManualMrz()
        {
            if (IsValidMrz(ManualMrz))
            {
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    PassportData = $"Manual MRZ submitted: {ManualMrz}";
                    MrzNotFound = string.Empty;
                });

                _secretsManager.SetMrzNumbers(ManualMrz);

                if (StartNfcCommand.CanExecute(null))
                {
                    StartNfcCommand.Execute(null);
                }
            }
            else
            {
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    MrzNotFound = "❌ Invalid MRZ format. Please check the input.";
                });
            }
        }

        private async Task ScanMrzAsync()
        {
            try
            {
                string scannedMrz = await Task.Run(() => "YOUR_SCANNED_MRZ_HERE");

                if (IsValidMrz(scannedMrz))
                {
                    ManualMrz = scannedMrz;
                    MrzNotFound = string.Empty;
                }
                else
                {
                    MrzNotFound = "❌ Invalid MRZ format. Please check the input.";
                }
            }
            catch (Exception ex)
            {
                MrzNotFound = $"⚠️ Error scanning MRZ: {ex.Message}";
            }
        }

        private static bool IsValidMrz(string mrz) => !string.IsNullOrWhiteSpace(mrz) && mrz.Length == 24;

        private void StartNfc()
        {
            try
            {
                _nfcReaderManager.StartListening();
                PassportData = "📡 NFC Reader started. Waiting for a tag...";
            }
            catch (Exception ex)
            {
                PassportData = $"⚠️ Error starting NFC: {ex.Message}";
            }
        }

        private void StopNfc()
        {
            try
            {
                _nfcReaderManager.StopListening();
                PassportData = "⏹ NFC Reader stopped.";
            }
            catch (Exception ex)
            {
                PassportData = $"⚠️ Error stopping NFC: {ex.Message}";
            }
        }

        private void OnPropertyChanged(string propertyName)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
