﻿using Android.Nfc;
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
            Console.WriteLine("Tag detected!");
            string[] techList = tag.GetTechList();

            Console.WriteLine("Supported NFC Technologies:");
            foreach (string tech in techList)
            {
                Console.WriteLine(tech);
            }

            // Check for specific NFC card types
            if (techList.Contains("android.nfc.tech.NfcA"))
            {
                Console.WriteLine("NfcA (Type A) detected.");
            }
            else if (techList.Contains("android.nfc.tech.NfcB"))
            {
                Console.WriteLine("NfcB (Type B) detected.");
            }
            else if (techList.Contains("android.nfc.tech.NfcF"))
            {
                Console.WriteLine("NfcF (Type F) detected.");
            }
            else if (techList.Contains("android.nfc.tech.NfcV"))
            {
                Console.WriteLine("NfcV (Type V/ISO15693) detected.");
            }
            else
            {
                Console.WriteLine("Unknown NFC type detected.");
            }
        }

    }
}
