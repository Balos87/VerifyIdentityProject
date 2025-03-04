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
                        // Identifiera bildformatet
                        string format = IdentifyImageFormat(_imageData);
                        Console.WriteLine($"Identifierat bildformat: {format}");

                        byte[] processedData;

                        if (format == "JPEG2000")
                        {
                            // Konvertera JPEG2000 till JPEG
                            processedData = JP2Converter.ConvertJP2ToJpeg(_imageData);

                            // Om konverteringen misslyckades, använd originaldatan
                            if (processedData == null)
                            {
                                Console.WriteLine("Konvertering misslyckades, använder originaldata");
                                processedData = _imageData;
                            }
                        }
                        else
                        {
                            // Om det inte är JPEG2000, använd originaldatan
                            processedData = _imageData;
                        }

                        // Uppdatera UI på UI-tråden
                        MainThread.BeginInvokeOnMainThread(() => {
                            PassportImage = ImageSource.FromStream(() => new MemoryStream(processedData));
                        });
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
            if (data == null || data.Length < 12)
                return "UNKNOWN";

            // JPEG signatur (börjar med FFD8FF)
            if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
                return "JPEG";

            // JPEG2000 JP2 signatur (börjar med 0000000C6A502020)
            if (data.Length > 8 &&
                data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x0C &&
                data[4] == 0x6A && data[5] == 0x50 && data[6] == 0x20 && data[7] == 0x20)
                return "JPEG2000";

            // Alternativ JPEG2000 J2K signatur (börjar med FF4FFF)
            if (data.Length > 3 && data[0] == 0xFF && data[1] == 0x4F && data[2] == 0xFF)
                return "JPEG2000";

            // PNG signatur (börjar med 89504E47)
            if (data.Length > 4 &&
                data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47)
                return "PNG";

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