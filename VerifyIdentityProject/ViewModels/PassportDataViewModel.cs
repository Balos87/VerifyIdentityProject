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
                        // Försök identifiera om det är JPEG2000 format
                        string format = IdentifyImageFormat(_imageData);
                        Console.WriteLine($"Identifierat bildformat: {format}");

                        byte[] processedData;

                        if (format == "JPEG2000")
                        {
                            // Konvertera JPEG2000 till JPEG
                            processedData = ImageHelper.ConvertJpeg2000ToJpeg(_imageData);
                        }
                        else
                        {
                            // Om det inte är JPEG2000, använd originaldatan
                            processedData = _imageData;
                        }

                        if (processedData != null)
                        {
                            // Uppdatera UI på UI-tråden
                            MainThread.BeginInvokeOnMainThread(() => {
                                PassportImage = ImageSource.FromStream(() => new MemoryStream(processedData));
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Fel vid bildinställning: {ex.Message}");
                    }
                }
            }
        }

        private string IdentifyImageFormat(byte[] data)
        {
            if (data.Length < 12)
                return "UNKNOWN";

            // JPEG signatur
            if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
                return "JPEG";

            // JPEG2000 JP2 signatur
            if (data.Length > 8 &&
                (data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x0C &&
                 data[4] == 0x6A && data[5] == 0x50))
                return "JPEG2000";

            // Alternativ JPEG2000 J2K signatur
            if (data.Length > 3 && data[0] == 0xFF && data[1] == 0x4F && data[2] == 0xFF)
                return "JPEG2000";

            return "UNKNOWN";
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