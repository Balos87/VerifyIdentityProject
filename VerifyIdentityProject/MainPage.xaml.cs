using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Resources.Interfaces;
using VerifyIdentityProject.Services;
using VerifyIdentityProject.ViewModels;

namespace VerifyIdentityProject
{
    public partial class MainPage : ContentPage
    {
        private MainPageViewModel _viewModel;

        public MainPage(MainPageViewModel viewModel, INfcReaderManager nfcReaderManager)
        {
            InitializeComponent();
            var copy = new CopySecrets();
            copy.CopySecretFileToAppData();
            copy.CopyAppSettingsFileToAppData();

            _viewModel = viewModel;
            BindingContext = _viewModel;
        }

    }
}
