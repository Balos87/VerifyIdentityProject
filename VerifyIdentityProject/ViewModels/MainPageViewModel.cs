using System.ComponentModel;
using System.Windows.Input;
using VerifyIdentityProject.Resources.Interfaces;

namespace VerifyIdentityProject
{
    public class MainPageViewModel : INotifyPropertyChanged
    {
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

        public MainPageViewModel(INfcReader nfcReader)
        {
            StartNfcCommand = new Command(() =>
            {
                try
                {
                    nfcReader.StartListening();
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