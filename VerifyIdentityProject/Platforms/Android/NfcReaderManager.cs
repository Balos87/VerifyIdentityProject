using Android.Nfc;
using Android.Nfc.Tech;
using Android.App;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Maui.Controls;
using VerifyIdentityProject.Resources.Interfaces;
using VerifyIdentityProject.Helpers;

namespace VerifyIdentityProject.Platforms.Android
{
    public class NfcReaderManager : INfcReaderManager
    {
        private readonly NfcAdapter _nfcAdapter;
        private readonly Activity _activity;

        // Events to notify about NFC interactions
        public event Action<string> OnNfcChipDetected;
        public event Action<string> OnNfcTagDetected;
        public event Action<string> OnNfcProcessingStarted;
        public event Action<string> OnNfcProcessingCompleted;

        public NfcReaderManager()
        {
            _activity = Platform.CurrentActivity!;
            _nfcAdapter = NfcAdapter.GetDefaultAdapter(_activity);
        }

        /// <summary>
        /// Starts listening for NFC tags.
        /// </summary>
        public void StartListening()
        {
            if (_nfcAdapter == null)
            {
                Console.WriteLine("❌ NFC is not supported on this device.");
                return;
            }

            if (!_nfcAdapter.IsEnabled)
            {
                Console.WriteLine("⚠️ NFC is disabled. Please enable it in settings.");
                return;
            }

            // Enable NFC reader mode
            _nfcAdapter.EnableReaderMode(
                _activity,
                new BacProcessor(this), // NFC tag discovery callback
                NfcReaderFlags.NfcA | NfcReaderFlags.NfcB | NfcReaderFlags.SkipNdefCheck,
                null
            );
            Console.WriteLine("\n🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰🟰");
            Console.WriteLine("📡 NFC Reader started. \nPlease place the device on the passport.");
            OnNfcChipDetected?.Invoke("📡 NFC Reader started. Please place the device on the passport.");
        }

        /// <summary>
        /// Stops NFC listening.
        /// </summary>
        public void StopListening()
        {
            if (_nfcAdapter != null)
            {
                _nfcAdapter.DisableReaderMode(_activity);
                Console.WriteLine("⏹ NFC Reader stopped.");
                OnNfcChipDetected?.Invoke("⏹ NFC Reader stopped.");
            }
        }

        /// <summary>
        /// 
        /// Identifies the detected NFC chip's technology.
        /// </summary>
        public void IdentifyTagTechnologies(Tag tag)
        {
            //Console.WriteLine("<- IdentifyTagTechnologies ->");
            string[] techList = tag.GetTechList();

            // Console.WriteLine("Detected NFC Chip Technologies:");
            foreach (string tech in techList)
            {
                Console.WriteLine(tech);
            }

            if (techList.Length == 0)
            {
                Console.WriteLine("No technology detected.");
            }
            Console.WriteLine("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");
        }

        /// <summary>
        /// Handles NFC tag discovery.
        /// </summary>
        public async void HandleTagDiscovered(Tag tag)
        {
            Console.WriteLine("➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖");
            Console.WriteLine("🔍 NFC Tag Detected!");
            OnNfcTagDetected?.Invoke("✅ NFC Tag Detected!");

            await Task.Delay(1000); // Short delay before processing starts

            try
            {
                IdentifyTagTechnologies(tag);
                IsoDep isoDep = IsoDep.Get(tag);

                if (isoDep != null)
                {
                    Console.WriteLine("⚡ ISO-DEP Tag detected. Starting PACE...");
                    OnNfcProcessingStarted?.Invoke("🔄 Performing PACE, please wait...");

                    // Fetch API URL the same way as MrzReader
                    var appsettings = GetSecrets.FetchAppSettings();
                    string apiUrl = await APIHelper.GetAvailableUrl(appsettings?.API_URL, appsettings?.LOCAL_SERVER);

                    // Perform PACE and retrieve MRZ data
                    var paceProcessorDG1 = new PaceProcessorDG1(isoDep);
                    Dictionary<string, string> mrz = paceProcessorDG1.PerformPaceDG1();

                    // Perform PACE and retrieve image data
                    var paceProcessorDG2 = new PaceProcessorDG2(isoDep);
                    var imgData = await paceProcessorDG2.PerformPaceDG2Async(apiUrl);

                    Console.WriteLine("🎉 PACE Successful!");
                    OnNfcProcessingCompleted?.Invoke("🎉 PACE Successful! Continuing...");

                    await Task.Delay(2000); // Pause before moving to next step

                    // Navigate to the PassportDataPage with the MRZ and image data
                    MainThread.BeginInvokeOnMainThread(async () =>
                    {
                        await Shell.Current.GoToAsync(nameof(PassportDataPage), true, new Dictionary<string, object>
                        {
                            { "DG1Data", mrz },
                            { "ImageData", imgData }
                        });
                    });
                }
                else
                {
                    Console.WriteLine("❌ Not an ISO-DEP (NFC-A/B) tag.");
                    OnNfcChipDetected?.Invoke("⚠️ NFC Chip detected but not supported.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error during NFC processing: {ex.Message}");
                OnNfcChipDetected?.Invoke($"❌ Error processing NFC: {ex.Message}");
            }
        }
    }
}
