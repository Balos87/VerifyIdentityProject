using Microsoft.Extensions.DependencyInjection;
using Microsoft.Maui.Controls;
using System;
using VerifyIdentityProject; // Import DeveloperLogPage

namespace VerifyIdentityProject
{
    public partial class AppShell : Shell
    {
        private readonly IServiceProvider _serviceProvider;

        public AppShell(IServiceProvider serviceProvider)
        {
            InitializeComponent();
            _serviceProvider = serviceProvider;

            // Register routes for navigation
            Routing.RegisterRoute(nameof(PassportDataPage), typeof(PassportDataPage));
            Routing.RegisterRoute(nameof(DeveloperLogPage), typeof(DeveloperLogPage));
            Routing.RegisterRoute(nameof(ScanQrPage), typeof(ScanQrPage));


            // Add MainPage to Shell items
            Items.Add(new ShellContent { Content = serviceProvider.GetRequiredService<MainPage>(), Route = nameof(MainPage) });

        }
    }
}
