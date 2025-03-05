using VerifyIdentityProject.ViewModels;
using Microsoft.Maui.Controls;
using System.Collections.Generic;

namespace VerifyIdentityProject
{
    [QueryProperty(nameof(DG1Data), "DG1Data")]
    public partial class DG1Page : ContentPage
    {
        private Dictionary<string, string> _dg1Data;
        public Dictionary<string, string> DG1Data
        {
            get => _dg1Data;
            set
            {
                _dg1Data = value;
                BindingContext = new DG1ViewModel(_dg1Data);
            }
        }

        public DG1Page()
        {
            InitializeComponent();
        }
    }
}
