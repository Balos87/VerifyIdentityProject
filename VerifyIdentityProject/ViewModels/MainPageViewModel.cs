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
        private string _manualMrz;
        private bool _isScanning;
        private bool _isMrzInfoVisible;
        private string _extractedMrz;

        public event PropertyChangedEventHandler? PropertyChanged;

        public ICommand StartNfcCommand { get; }
        public ICommand StopNfcCommand { get; }
        public ICommand SubmitManualMrzCommand { get; }
        public ICommand ScanMrzCommand { get; set; }
        public ICommand ShowMrzInfoCommand { get; }
        public ICommand HideMrzInfoCommand { get; }

        public string ExtractedMrz
        {
            get => _extractedMrz;
            set
            {
                if (_extractedMrz != value)
                {
                    _extractedMrz = value;
                    OnPropertyChanged(nameof(ExtractedMrz));
                }
            }
        }
        public string ManualMrz
        {
            get => _manualMrz;
            set
            {
                if (_manualMrz != value)
                {
                    _manualMrz = value;
                    OnPropertyChanged(nameof(ManualMrz));

                    // ✅ Show status update in PassportData (Status Message Window)
                    if (IsValidMrz(_manualMrz))
                    {
                        PassportData = $"✅ Manual MRZ submitted: {_manualMrz}";
                    }
                    else
                    {
                        PassportData = "❌ Invalid MRZ format. Please check the input.";
                    }
                }
            }
        }
        public bool IsMrzInfoVisible
        {
            get => _isMrzInfoVisible;
            set
            {
                if (_isMrzInfoVisible != value)
                {
                    _isMrzInfoVisible = value;
                    OnPropertyChanged(nameof(IsMrzInfoVisible));
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

            ExtractedMrz = "";

            _secretsManager = new SecretsManager(_secretsFilePath);
            StartNfcCommand = new Command(StartNfc);
            StopNfcCommand = new Command(StopNfc);
            SubmitManualMrzCommand = new Command(SubmitManualMrz);
            ScanMrzCommand = new Command(async () => await ScanMrzAsync());

            ShowMrzInfoCommand = new Command(() => IsMrzInfoVisible = true);
            HideMrzInfoCommand = new Command(() => IsMrzInfoVisible = false);
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

        private async Task ScanMrzAsync()
        {
            try
            {
                var mrzReader = new MrzReader(UpdatePassportData, _nfcReaderManager);
                await mrzReader.ScanAndExtractMrzAsync();
            }
            catch (Exception ex)
            {
                PassportData = $"⚠️ Error capturing MRZ: {ex.Message}";
            }
        }

        private void UpdateCaptureSection(string mrzValue)
        {
            Console.WriteLine($"📜 MRZ FOR CAPTURE SECTION : {mrzValue}");
            ExtractedMrz = $"📜 MRZ Found: {mrzValue}";
            OnPropertyChanged(nameof(ExtractedMrz));  // ✅ Ensure UI updates
        }


        private async void UpdatePassportData(string message)
        {
            if (message.StartsWith("MRZ:"))
            {
                // ✅ Extract MRZ value
                string mrzValue = message.Replace("MRZ:", "").Trim();

                // ✅ Update ExtractedMrz with full message
                ExtractedMrz = $"Captured MRZ from photo: {mrzValue}";
            }
            else
            {
                // ✅ Use PassportData only for status messages
                PassportData = message;
            }
        }


        private async void SubmitManualMrz()
        {
            if (IsValidMrz(ManualMrz))
            {
                // ✅ Show MRZ found message before proceeding
                PassportData = $"📜 MRZ Found: {ManualMrz}";

                _secretsManager.SetMrzNumbers(ManualMrz);

                await Task.Delay(5000); // ⏳ Wait for 5 seconds

                // ✅ Now start NFC after delay
                PassportData = "📡 NFC Reader started. Please place the device on the passport.";
                StartNfcCommand.Execute(null);
            }
            else
            {
                PassportData = "❌ Invalid MRZ format. Please check the input.";
            }
        }


        private static bool IsValidMrz(string mrz) => !string.IsNullOrWhiteSpace(mrz) && mrz.Length == 24;

        private void StartNfc()
        {
            try
            {
                _nfcReaderManager.StartListening();
                PassportData = "📡 NFC Reader started. Please place the device on the passport.";
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
