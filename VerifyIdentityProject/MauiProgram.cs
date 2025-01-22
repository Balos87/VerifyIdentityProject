﻿using Microsoft.Extensions.Logging;
using VerifyIdentityProject;
using VerifyIdentityProject.Resources.Interfaces;
using TesseractOcrMaui;
using VerifyIdentityProject.Helpers.MRZReader;

public static class MauiProgram
{
    public static IServiceProvider Services { get; private set; }
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
            });

        builder.Services
        .AddTesseractOcr();

        builder.Services.AddSingleton<AppShell>();
        builder.Services.AddTransient<MainPageViewModel>();
        builder.Services.AddTransient<MainPage>();
        builder.Services.AddTransient<MrzReader>();

#if ANDROID
        builder.Services.AddSingleton<INfcReaderManager, VerifyIdentityProject.Platforms.Android.NfcReaderManager>();
#endif

        var app = builder.Build();
        Services = app.Services;
        return app;
    }
}
