using Microsoft.Maui.Controls;
using VerifyIdentityProject.ViewModels;

namespace VerifyIdentityProject
{
    public partial class DeveloperLogPage : ContentPage
    {
        public DeveloperLogPage()
        {
            InitializeComponent();
            BindingContext = DebugLogViewModel.Instance;
        }
    }
}
