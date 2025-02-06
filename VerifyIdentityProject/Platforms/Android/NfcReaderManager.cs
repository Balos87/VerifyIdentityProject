using Android.Nfc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using VerifyIdentityProject.Resources.Interfaces;
using Android.App;
using Android.Nfc.Tech;
using VerifyIdentityProject.Helpers;
using System.Security.Cryptography;
using Xamarin.Google.Crypto.Tink.Subtle;
using Microsoft.Maui.Controls;
using Xamarin.Google.Crypto.Tink.Shaded.Protobuf;

namespace VerifyIdentityProject.Platforms.Android
{
    public class NfcReaderManager : INfcReaderManager
    {
        private NfcAdapter _nfcAdapter;
        private Activity _activity;

        public NfcReaderManager()
        {
            _activity = Platform.CurrentActivity!;
            _nfcAdapter = NfcAdapter.GetDefaultAdapter(_activity);
        }

        /// <summary>
        /// Starts listening for NFC tags.
        /// </summary>
        /// <remarks>
        /// This method checks if the NFC adapter is available and enabled.
        /// If valid, it enables NFC reader mode with specified flags and a callback to handle NFC tag discovery.
        /// </remarks>
        /// <param name="NfcReaderFlags">Flags specifying the types of NFC tags to detect (e.g., NfcA, NfcB).</param>
        /// <exception cref="InvalidOperationException">Thrown if the NFC adapter is not available or enabled.</exception>
        public void StartListening()
        {
            // Check if NFC adapter is available and enabled
            if (_nfcAdapter == null || !_nfcAdapter.IsEnabled)
            {
                Console.WriteLine("NFC not supported or not enabled.");
                return;
            }

            // Enable NFC reader mode
            _nfcAdapter.EnableReaderMode(
                _activity, // The current activity
                new BacProcessor(this), // Callback for handling NFC tag discovery
                NfcReaderFlags.NfcA | NfcReaderFlags.NfcB | NfcReaderFlags.SkipNdefCheck,
                null
            );
        }

        public void StopListening()
        {
            _nfcAdapter.DisableReaderMode(_activity);
        }

        public void IdentifyTagTechnologies(Tag tag)
        {
            Console.WriteLine("<-IdentifyTagTechnologies->");
            string[] techList = tag.GetTechList();

            Console.WriteLine("______This NFC-Chip Technologies:");
            foreach (string tech in techList)
            {
                Console.WriteLine(tech);

            }
            if (techList == null || techList.Length == 0)
            {
                Console.WriteLine("No tech was found");
            }
            Console.WriteLine("");
            Console.WriteLine("<---------------------------------------->");
            Console.WriteLine("");
        }

        public void HandleTagDiscovered(Tag tag)
        {
            Console.WriteLine("<-HandleTagDiscovered->");
            Console.WriteLine("");
            Console.WriteLine("");
            Console.WriteLine("-----------------------------------------------------------");
            Console.WriteLine("<<<-------           Verify Identity             ------->>>");
            Console.WriteLine("-----------------------------------------------------------");
            Console.WriteLine("");
            Console.WriteLine("");
            Console.WriteLine("<---------------------------------------->");
            Console.WriteLine("");

            try
            {
                IdentifyTagTechnologies(tag);
                IsoDep isoDep = IsoDep.Get(tag);
                PaceProcessor.PerformPace(isoDep);
                //if (isoDep != null)
                //{
                //    BacProcessor.ProcessBac(isoDep);
                //}
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during NFC processing: {ex.Message}");
            }
        }


    }
}