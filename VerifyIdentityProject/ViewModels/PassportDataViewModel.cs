using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using Microsoft.Maui.Controls;

namespace VerifyIdentityProject
{
    public class PassportDataViewModel : INotifyPropertyChanged
    {
        private Dictionary<string, string> _dg1Data;
        private byte[] _imageData;
        private ImageSource _passportImage;

        public Dictionary<string, string> DG1Data
        {
            get => _dg1Data;
            set
            {
                _dg1Data = value;
                OnPropertyChanged();
            }
        }

        public byte[] ImageData
        {
            get => _imageData;
            set
            {
                _imageData = value;
                OnPropertyChanged();

                if (_imageData != null && _imageData.Length > 0)
                {
                    try
                    {
                        // Konvertera bilden om det är JPEG2000
                        byte[] processedImageData = ImageHelper.ConvertJpeg2000ToJpeg(_imageData);

                        // Skapa ImageSource från den bearbetade bilddatan
                        MainThread.BeginInvokeOnMainThread(() => {
                            PassportImage = ImageSource.FromStream(() => new MemoryStream(processedImageData));
                        });
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Fel vid bildinställning: {ex.Message}");
                    }
                }
            }
        }

        public ImageSource PassportImage
        {
            get => _passportImage;
            set
            {
                _passportImage = value;
                OnPropertyChanged();
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;

        protected virtual void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}