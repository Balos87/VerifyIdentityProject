namespace VerifyIdentityProject
{
    public partial class AppShell : Shell
    {
        private readonly IServiceProvider _serviceProvider;

        public AppShell(IServiceProvider serviceProvider)
        {
            InitializeComponent();
            _serviceProvider = serviceProvider;

            // Example: Using the service provider to resolve MainPage
            Items.Add(new ShellContent { Content = serviceProvider.GetRequiredService<MainPage>() });

        }
    }


}
