using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.Helpers.MRZReader;
using VerifyIdentityProject.Resources.Interfaces;

namespace VerifyIdentityProject
{
    public partial class MainPage : ContentPage
    {
        private MainPageViewModel _viewModel;
        private MrzReader _mrzReader;
        public MainPage(MainPageViewModel viewModel, INfcReaderManager nfcReaderManager)
        {
            InitializeComponent();
            var copy = new CopySecrets();
            copy.CopySecretFileToAppData();

            _viewModel = viewModel;
            _mrzReader = new MrzReader(UpdateMrzNotFoundMessage, nfcReaderManager);
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
