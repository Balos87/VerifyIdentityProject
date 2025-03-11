using Microsoft.Extensions.Logging;
using VerifyIdentityProject;
using VerifyIdentityProject.Resources.Interfaces;
using TesseractOcrMaui;
using SkiaSharp.Views.Maui.Controls.Hosting;
using VerifyIdentityProject.Services;
using VerifyIdentityProject.ViewModels;

public static class MauiProgram
{
    public static IServiceProvider Services { get; private set; }
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();
        builder
            .UseMauiApp<App>()
            .UseSkiaSharp()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
            });

        builder.Services.AddSingleton<System.Action<System.String>>(str => { });
        builder.Services.AddSingleton<AppShell>();
        builder.Services.AddTransient<MainPageViewModel>();
        builder.Services.AddTransient<MainPage>();
        builder.Services.AddSingleton<MrzReader>();
        builder.Services.AddSingleton<Jpeg2000Converter>();
        builder.Services.AddSingleton<DebugLogViewModel>();

#if ANDROID
        builder.Services.AddSingleton<INfcReaderManager, VerifyIdentityProject.Platforms.Android.NfcReaderManager>();
#endif

        var app = builder.Build();
        Services = app.Services;
        return app;
    }
}
