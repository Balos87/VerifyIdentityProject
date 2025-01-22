using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Helpers.MRZReader;
using VerifyIdentityProject.Resources.Interfaces;
using Microsoft.Maui.Controls;
using Tesseract;

namespace VerifyIdentityProject
{
    public partial class MainPage : ContentPage
    {
        private readonly MainPageViewModel _viewModel;
        private MrzReader _mrzReader;

        public MainPage(MrzReader mrzReader ,MainPageViewModel viewModel)
        {
            InitializeComponent();
            var copy = new CopySecrets();
            copy.CopySecretFileToAppData();

            _viewModel = viewModel;
            BindingContext = _viewModel;

            _mrzReader = mrzReader;
            BindingContext = _mrzReader;
        }
    }
}
