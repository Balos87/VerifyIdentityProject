using System.ComponentModel;
using System.Windows.Input;
using VerifyIdentityProject.Resources.Interfaces;

namespace VerifyIdentityProject
{
    public class MainPageViewModel : INotifyPropertyChanged
    {

        private string _processedImagePath;

        public string ProcessedImagePath
        {
            get => _processedImagePath;
            set
            {
                if (_processedImagePath != value)
                {
                    _processedImagePath = value;
                    OnPropertyChanged(nameof(ProcessedImagePath));
                }
            }
        }

        private string _passportData;
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

        public MainPageViewModel(INfcReaderManager nfcReaderManager)
        {
            StartNfcCommand = new Command(() =>
            {
                try
                {
                    nfcReaderManager.StartListening();
                    PassportData = "NFC Reader started. Waiting for a tag...";
                }
                catch (Exception ex)
                {
                    PassportData = $"Error starting NFC: {ex.Message}";
                }
            });
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}