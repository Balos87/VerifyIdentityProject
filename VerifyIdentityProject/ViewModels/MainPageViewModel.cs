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
            set => SetProperty(ref _extractedMrz, value);
        }

        public string ManualMrz
        {
            get => _manualMrz;
            set
            {
                if (SetProperty(ref _manualMrz, value))
                {
                    PassportData = IsValidMrz(_manualMrz)
                        ? string.Format(MauiStatusMessageHelper.MrzFoundMessage, _manualMrz)
                        : MauiStatusMessageHelper.MrzInvalidMessage;
                }
            }
        }

        public bool IsMrzInfoVisible
        {
            get => _isMrzInfoVisible;
            set => SetProperty(ref _isMrzInfoVisible, value);
        }

        public string PassportData
        {
            get => _passportData;
            set => SetProperty(ref _passportData, value);
        }

        public bool IsScanning
        {
            get => _isScanning;
            set => SetProperty(ref _isScanning, value);
        }

        public MainPageViewModel(INfcReaderManager nfcReaderManager)
        {
            _nfcReaderManager = nfcReaderManager ?? throw new ArgumentNullException(nameof(nfcReaderManager));

            _nfcReaderManager.OnNfcChipDetected += message => SetPassportStatusMessage(message);
            _nfcReaderManager.OnNfcTagDetected += message => SetPassportStatusMessage(message);
            _nfcReaderManager.OnNfcProcessingStarted += message => {
                SetPassportStatusMessage(message);
                IsScanning = true;
            };
            _nfcReaderManager.OnNfcProcessingCompleted += async message => {
                SetPassportStatusMessage(message);
                await Task.Delay(2000);
                IsScanning = false;
            };

            ExtractedMrz = "";
            _secretsManager = new SecretsManager(_secretsFilePath);
            StartNfcCommand = new Command(StartNfc);
            StopNfcCommand = new Command(StopNfc);
            SubmitManualMrzCommand = new Command(SubmitManualMrz);
            ScanMrzCommand = new Command(async () => await ScanMrzAsync());
            ShowMrzInfoCommand = new Command(() => IsMrzInfoVisible = true);
            HideMrzInfoCommand = new Command(() => IsMrzInfoVisible = false);
        }

        private void SetPassportStatusMessage(string message)
        {
            MainThread.BeginInvokeOnMainThread(() =>
            {
                if (message.StartsWith("MRZ:"))
                {
                    string mrzValue = message.Replace("MRZ:", "").Trim();
                    ExtractedMrz = $"Captured MRZ from photo: {mrzValue}"; // ✅ Ensure MRZ is displayed
                }
                else
                {
                    PassportData = message;
                }
            });
        }

        private async Task ScanMrzAsync()
        {
            try
            {
                var mrzReader = new MrzReader(SetPassportStatusMessage, _nfcReaderManager);
                await mrzReader.ScanAndExtractMrzAsync();
            }
            catch (Exception ex)
            {
                SetPassportStatusMessage(string.Format(MauiStatusMessageHelper.MrzScanningErrorMessage, ex.Message));
            }
        }

        private async void SubmitManualMrz()
        {
            if (IsValidMrz(ManualMrz))
            {
                SetPassportStatusMessage(string.Format(MauiStatusMessageHelper.MrzFoundMessage, ManualMrz));
                _secretsManager.SetMrzNumbers(ManualMrz);
                await Task.Delay(5000);
                StartNfc();
            }
            else
            {
                SetPassportStatusMessage(MauiStatusMessageHelper.MrzInvalidMessage);
            }
        }

        private static bool IsValidMrz(string mrz) => !string.IsNullOrWhiteSpace(mrz) && mrz.Length == 24;

        private void StartNfc()
        {
            try
            {
                _nfcReaderManager.StartListening();
                SetPassportStatusMessage(MauiStatusMessageHelper.NfcReaderStartedMessage);
            }
            catch (Exception ex)
            {
                SetPassportStatusMessage(string.Format(MauiStatusMessageHelper.NfcErrorMessage, ex.Message));
            }
        }

        private void StopNfc()
        {
            try
            {
                _nfcReaderManager.StopListening();
                SetPassportStatusMessage(MauiStatusMessageHelper.NfcReaderStoppedMessage);
            }
            catch (Exception ex)
            {
                SetPassportStatusMessage(string.Format(MauiStatusMessageHelper.NfcErrorMessage, ex.Message));
            }
        }

        private bool SetProperty<T>(ref T storage, T value, [System.Runtime.CompilerServices.CallerMemberName] string propertyName = null)
        {
            if (EqualityComparer<T>.Default.Equals(storage, value)) return false;
            storage = value;
            OnPropertyChanged(propertyName);
            return true;
        }

        private void OnPropertyChanged(string propertyName)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}