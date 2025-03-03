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
            Routing.RegisterRoute(nameof(DG1Page), typeof(DG1Page));

            // Example: Using the service provider to resolve MainPage
            Items.Add(new ShellContent { Content = serviceProvider.GetRequiredService<MainPage>() });
            Routing.RegisterRoute(nameof(DgInformationFetchedPage), typeof(DgInformationFetchedPage));


        }
    }
}
