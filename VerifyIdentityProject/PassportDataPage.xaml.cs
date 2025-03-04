using System.Collections.Generic;
using Microsoft.Maui.Controls;

namespace VerifyIdentityProject
{
    [QueryProperty(nameof(DG1Data), "DG1Data")]
    [QueryProperty(nameof(ImageData), "ImageData")]
    public partial class PassportDataPage : ContentPage
    {
        private PassportDataViewModel _viewModel;

        public PassportDataPage()
        {
            InitializeComponent();
            _viewModel = new PassportDataViewModel();
            BindingContext = _viewModel;
        }

        public Dictionary<string, string> DG1Data
        {
            set
            {
                if (value != null)
                {
                    _viewModel.DG1Data = value;
                }
            }
        }

        public byte[] ImageData
        {
            set
            {
                if (value != null)
                {
                    _viewModel.ImageData = value;
                }
            }
        }
    }
}