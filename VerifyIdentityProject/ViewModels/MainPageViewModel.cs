using System.ComponentModel;
using System.Windows.Input;
using VerifyIdentityProject.Helpers.MRZReader;
using VerifyIdentityProject.Resources.Interfaces;

namespace VerifyIdentityProject
{
    public class MainPageViewModel : INotifyPropertyChanged
    {

        public ICommand ScanMrzCommand { get; }

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

        public MainPageViewModel(INfcReaderManager nfcReaderManager, MrzReader mrzReader)
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

            if (mrzReader == null)
                throw new ArgumentNullException(nameof(mrzReader));

            // Assign the command from MrzReader
            ScanMrzCommand = new Command(async () => await mrzReader.ScanAndExtractMrzAsync());
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}