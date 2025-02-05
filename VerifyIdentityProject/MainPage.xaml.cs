using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Helpers.MRZReader;

namespace VerifyIdentityProject
{
    public partial class MainPage : ContentPage
    {
        private MainPageViewModel _viewModel;
        private MrzReader _mrzReader;
        public MainPage(MainPageViewModel viewModel)
        {
            InitializeComponent();
            var copy = new CopySecrets();
            copy.CopySecretFileToAppData();

            _viewModel = viewModel;
            _mrzReader = new MrzReader(UpdateMrzNotFoundMessage);
            BindingContext = _viewModel;

            // Assign the command from MrzReader
            _viewModel.ScanMrzCommand = new Command(async () => await _mrzReader.ScanAndExtractMrzAsync());
        }
        private void UpdateMrzNotFoundMessage(string message)
        {
            _viewModel.MrzNotFound = message;
        }
    }
}
