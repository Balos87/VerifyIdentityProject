using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace VerifyIdentityProject.ViewModels
{
    public class DG1ViewModel : INotifyPropertyChanged
    {
        private Dictionary<string, string> _dg1Data;

        public Dictionary<string, string> DG1Data
        {
            get => _dg1Data;
            set
            {
                _dg1Data = value;
                OnPropertyChanged();
            }
        }

        public DG1ViewModel(Dictionary<string, string> dg1Data)
        {
            DG1Data = dg1Data;
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
