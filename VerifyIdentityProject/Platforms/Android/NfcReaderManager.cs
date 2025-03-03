using Android.Nfc;
using Android.Nfc.Tech;
using Android.App;
using Android.Util;
using VerifyIdentityProject.Resources.Interfaces;
using VerifyIdentityProject.Helpers;
using System;
using System.Text;
using Microsoft.Maui.Controls;

namespace VerifyIdentityProject.Platforms.Android
{
    public class NfcReaderManager : INfcReaderManager
    {
        private readonly NfcAdapter _nfcAdapter;
        private readonly Activity _activity;

        // Event to notify when an NFC chip is detected
        public event Action<string> OnNfcChipDetected;

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
                Console.WriteLine("NFC is not supported on this device.");
                return;
            }

            if (!_nfcAdapter.IsEnabled)
            {
                Console.WriteLine("NFC is disabled. Please enable it in settings.");
                return;
            }

            // Enable NFC reader mode
            _nfcAdapter.EnableReaderMode(
                _activity,
                new BacProcessor(this), // NFC tag discovery callback
                NfcReaderFlags.NfcA | NfcReaderFlags.NfcB | NfcReaderFlags.SkipNdefCheck,
                null
            );

            Console.WriteLine("NFC Reader started. Waiting for a tag...");
            OnNfcChipDetected?.Invoke("NFC Reader started. Waiting for a tag...");
        }

        /// <summary>
        /// Stops NFC listening.
        /// </summary>
        public void StopListening()
        {
            if (_nfcAdapter != null)
            {
                _nfcAdapter.DisableReaderMode(_activity);
                Console.WriteLine("NFC Reader stopped.");
                OnNfcChipDetected?.Invoke("NFC Reader stopped.");
            }
        }

        /// <summary>
        /// Identifies the technologies of the detected NFC chip.
        /// </summary>
        /// <param name="tag">Detected NFC tag</param>
        public void IdentifyTagTechnologies(Tag tag)
        {
            Console.WriteLine("<- IdentifyTagTechnologies ->");
            string[] techList = tag.GetTechList();

            Console.WriteLine("______ Detected NFC Chip Technologies:");
            foreach (string tech in techList)
            {
                Console.WriteLine(tech);
            }

            if (techList.Length == 0)
            {
                Console.WriteLine("No technology detected.");
            }

            Console.WriteLine("<---------------------------------------->");
        }

        /// <summary>
        /// Handles NFC tag discovery and starts processing.
        /// </summary>
        /// <param name="tag">Detected NFC tag</param>
        public void HandleTagDiscovered(Tag tag)
        {
            Console.WriteLine("<- HandleTagDiscovered ->");
            Console.WriteLine("-----------------------------------------------------------");
            Console.WriteLine("<<<-------           Verify Identity             ------->>>");
            Console.WriteLine("-----------------------------------------------------------");

            try
            {
                IdentifyTagTechnologies(tag);

                IsoDep isoDep = IsoDep.Get(tag);
                if (isoDep != null)
                {
                    Console.WriteLine("ISO-DEP Tag detected. Starting PACE...");
                    //BacProcessor bacProcessor = new BacProcessor(this);
                    //bacProcessor.ProcessBac(isoDep);
                    Dictionary<string, string> mrz = PaceProcessorDG1.PerformPaceDG1(isoDep);
                    var img = PaceProcessorDG2.PerformPaceDG2(isoDep);

                    Console.WriteLine($"Ready to send imgage. length: {img.Length}");

                    Console.WriteLine($"Ready to send mrz data:");
                    foreach (var field in mrz)
                    {
                        Console.WriteLine($"{field.Key}: {field.Value}");
                    }
                    // Trigger event to notify that an NFC chip was detected
                    OnNfcChipDetected?.Invoke("RFID Chip detected! Processing data...");
                }
                else
                {
                    Console.WriteLine("Not an ISO-DEP (NFC-A/B) tag.");
                    OnNfcChipDetected?.Invoke("NFC Chip detected but not supported.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during NFC processing: {ex.Message}");
                OnNfcChipDetected?.Invoke($"Error processing NFC: {ex.Message}");
            }
        }
    }
}
