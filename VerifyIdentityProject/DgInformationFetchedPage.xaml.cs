using Microsoft.Maui.Controls;
using System.IO;

namespace VerifyIdentityProject
{
    [QueryProperty(nameof(ImageData), "ImageData")] // Enables Shell Navigation Parameter
    public partial class DgInformationFetchedPage : ContentPage
    {
        private byte[] _imageData;
        public byte[] ImageData
        {
            get => _imageData;
            set
            {
                _imageData = value;
                OnPropertyChanged(nameof(ImageData)); // Force UI update

                if (_imageData != null && PassportImage != null)
                {
                    PassportImage.Source = ImageSource.FromStream(() => new MemoryStream(_imageData));
                }
            }
        }

        public DgInformationFetchedPage()
        {
            InitializeComponent();
        }
    }
}
