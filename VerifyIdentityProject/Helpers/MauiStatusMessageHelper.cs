using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    public static class MauiStatusMessageHelper
    {
        public const string NfcReaderStartedMessage = "📡 NFC Reader started. Please place the device on the passport.";
        public const string NfcReaderStoppedMessage = "⏹ NFC Reader stopped.";
        public const string NfcErrorMessage = "⚠️ Error During Process: {0}";
        public const string NfcChipDetectedMessage = "✅ NFC Chip Detected!";
        public const string NfcProcessingStartedMessage = "🔄 Performing PACE, please wait...";
        public const string NfcProcessingCompletedMessage = "🎉 PACE Successful! Continuing...";
        public const string NfcUnsupportedChipMessage = "⚠️ NFC Chip detected but not supported.";
        public const string NfcTagLostMessage = "⚠️ NFC Tag Lost! Please start the process over.";

        public const string MrzFoundMessage = "📜 MRZ Found: {0}";
        public const string MrzInvalidMessage = "❌ Invalid MRZ format. Please check the input.";
        public const string MrzExtractedMessage = "✅ MRZ Extracted: {0}";
        public const string MrzNotDetectedMessage = "❌ No MRZ detected in the image.";
        public const string MrzScanningErrorMessage = "⚠️ Error during scanning picture for MRZ. Try again!";
        public const string MrzProcessingMessage = "The image is being processed, please wait...";
    }
}
