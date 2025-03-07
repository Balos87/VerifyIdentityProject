using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui.Controls;
using System;

namespace VerifyIdentityProject
{
    public partial class AppShell : Shell
    {
        private readonly IServiceProvider _serviceProvider;

        public AppShell(IServiceProvider serviceProvider)
        {
            InitializeComponent();
            _serviceProvider = serviceProvider;

            // Register DG1Page for navigation
            Routing.RegisterRoute(nameof(PassportDataPage), typeof(PassportDataPage));

            Items.Add(new ShellContent { Content = serviceProvider.GetRequiredService<MainPage>() });

        }
    }
}
