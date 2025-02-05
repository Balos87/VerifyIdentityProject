using System.ComponentModel;
using System.Windows.Input;
using VerifyIdentityProject.Helpers.MRZReader;
using VerifyIdentityProject.Resources.Interfaces;

namespace VerifyIdentityProject
{
    public class MainPageViewModel : INotifyPropertyChanged
    {

        private string _mrzNotFound;
        private ICommand _scanMrzCommand;
        public ICommand ScanMrzCommand
        {
            get => _scanMrzCommand;
            set
            {
                _scanMrzCommand = value;
                OnPropertyChanged(nameof(ScanMrzCommand)); // Notify the UI about the updated command
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
        public MainPageViewModel()
        {
        }
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