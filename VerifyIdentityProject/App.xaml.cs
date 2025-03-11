using Microsoft.Maui.Dispatching;
using Microsoft.Extensions.DependencyInjection;
using VerifyIdentityProject.Helpers;
using VerifyIdentityProject.ViewModels;
using System;
using System.Diagnostics;

namespace VerifyIdentityProject
{
    public partial class App : Application
    {
        public App()
        {
            InitializeComponent();

            // Redirect Console output to DebugLogViewModel
            Console.SetOut(new DebugTextWriter(text =>
            {
                // Ensure UI updates happen on the main thread
                MainThread.BeginInvokeOnMainThread(() =>
                {
                    DebugLogViewModel.Instance.AppendLog(text);
                });
            }));
        }

        protected override Window CreateWindow(IActivationState? activationState)
        {
            var serviceProvider = MauiProgram.Services; // Resolve the service provider
            return new Window(serviceProvider.GetRequiredService<AppShell>());
        }
    }
}
