using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Resources.Interfaces;

namespace VerifyIdentityProject
{
    public partial class MainPage : ContentPage
    {
        public MainPage(MainPageViewModel viewModel)
        {
            InitializeComponent();
            var copy = new CopySecrets();
            copy.CopySecretFileToAppData();
            BindingContext = viewModel;
        }
    }
}
