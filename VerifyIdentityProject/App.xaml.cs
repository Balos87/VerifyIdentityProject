namespace VerifyIdentityProject
{
    public partial class App : Application
    {
        public App()
        {
            InitializeComponent();
        }

        protected override Window CreateWindow(IActivationState? activationState)
        {
            var serviceProvider = MauiProgram.Services; // Resolve the service provider
            return new Window(serviceProvider.GetRequiredService<AppShell>());
        }

    }
}