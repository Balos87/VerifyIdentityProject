using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using Microsoft.Maui.Controls;
using VerifyIdentityProject.Helpers;

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
                        // Använd vår SkiaSharp-baserade hjälpare för att behandla bilden
                        byte[] processedImage = SkiaImageHelper.ProcessImage(_imageData);

                        if (processedImage != null)
                        {
                            MainThread.BeginInvokeOnMainThread(() => {
                                PassportImage = ImageSource.FromStream(() => new MemoryStream(processedImage));
                                Console.WriteLine("Image processed and set in UI"); 
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error setting image: {ex.Message}");
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