using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.ComponentModel;
using System.Windows.Input;
using Microsoft.Maui.ApplicationModel;

namespace VerifyIdentityProject.ViewModels
{
    public class DebugLogViewModel : INotifyPropertyChanged
    {
        public ICommand CopyLogCommand { get; }
        public static DebugLogViewModel Instance { get; } = new DebugLogViewModel();

        private string _logText = string.Empty;
        public string LogText
        {
            get => _logText;
            set
            {
                if (_logText != value)
                {
                    _logText = value;
                    OnPropertyChanged(nameof(LogText));
                }
            }
        }

        public DebugLogViewModel()
        {
            CopyLogCommand = new Command(() => {
                if (!string.IsNullOrEmpty(LogText))
                {
                    Clipboard.SetTextAsync(LogText);
                }
            });
        }

        public void AppendLog(string text)
        {
            LogText += text + Environment.NewLine;

            #if ANDROID
                string documentsPath = Path.Combine(Android.OS.Environment.ExternalStorageDirectory.AbsolutePath, "Documents");
            #else
                string documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            #endif

            var filePath = Path.Combine(documentsPath, "log.txt");

            if (!Directory.Exists(documentsPath))
            {
                Directory.CreateDirectory(documentsPath);
            }

            File.WriteAllText(filePath, LogText);
        }

        public event PropertyChangedEventHandler PropertyChanged;
        protected virtual void OnPropertyChanged(string propertyName) =>
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

}
