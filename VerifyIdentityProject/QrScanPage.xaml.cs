using ZXing;

namespace VerifyIdentityProject
{
    public partial class QrScanPage : ContentPage
    {
        private string? qrData = "";
        public QrScanPage()
        {
            this.InitializeComponent();

            ////for QR-code reader
            //barcodeReader.Options = new ZXing.Net.Maui.BarcodeReaderOptions
            //{
            //    Formats = ZXing.Net.Maui.BarcodeFormat.QrCode,
            //    AutoRotate = true,
            //    Multiple = true,
            //    TryHarder = true,
            //};
        }


        //private void barcodeReader_BarcodesDetected(object sender, ZXing.Net.Maui.BarcodeDetectionEventArgs e)
        //{
        //    //runs it on the main thread. 
        //    MainThread.BeginInvokeOnMainThread(() =>
        //    {
        //        qrData = e.Results.FirstOrDefault()?.Value;
        //        barcodeReader.IsVisible = false;
        //        barcodeReader.IsDetecting = false;
        //        cancelButton.IsEnabled = false;
        //        DisplayAlert("QR data:", qrData, "OK");
        //    });
        //}

        //private async void OnStartScanningClicked(object sender, EventArgs e)
        //{
        //    Permissions.RequestAsync<Permissions.Camera>();
        //    var status = Permissions.CheckStatusAsync<Permissions.Camera>();
        //    if (status.Result.Equals("Granted"))
        //    {
        //        Console.WriteLine("Asking for Camera permission...");
        //        status = Permissions.RequestAsync<Permissions.Camera>();
        //        Console.WriteLine($"New Camera permission status: {status}");
        //    }
        //    await Task.Delay(100);
        //    barcodeReader.IsDetecting = true;
        //    barcodeReader.IsVisible = true;
        //    cancelButton.IsEnabled = true;
        //}

        //private void CancelScanning(object sender, EventArgs e)
        //{

        //    barcodeReader.IsVisible = false;
        //    barcodeReader.IsDetecting = false;
        //    cancelButton.IsEnabled = false;
        //}
    }
}
