using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    public class MRZByteParser
    {
        public static string ParseMRZBytes(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
                return string.Empty;

            StringBuilder mrz = new StringBuilder();
            bool startedReading = false;

            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];

                // Start reading after we find 'P' or '<'
                if (!startedReading && (b == 0x50 || b == 0x3C))
                {
                    startedReading = true;
                }

                if (startedReading)
                {
                    // Include only valid MRZ characters
                    if ((b >= 0x30 && b <= 0x39) ||  // Numbers
                        (b >= 0x41 && b <= 0x5A) ||  // Uppercase letters
                        b == 0x3C)                   // < symbol
                    {
                        mrz.Append((char)b);
                    }
                }
            }

            string result = mrz.ToString();

            // Ensure the result has the correct length for MRZ (44 characters per row)
            if (result.Length >= 88)
            {
                return result.Substring(0, 88);
            }

            // Pad with '<' characters if needed
            return result.PadRight(88, '<');
        }

        public static string FormatMRZForBAC(string mrz)
        {
            // Ensure we have exactly two rows of 44 characters each
            string[] lines = new string[2];

            if (mrz.Length >= 44)
            {
                lines[0] = mrz.Substring(0, 44);
                lines[1] = mrz.Length >= 88 ? mrz.Substring(44, 44) : mrz.Substring(44).PadRight(44, '<');
            }
            else
            {
                lines[0] = mrz.PadRight(44, '<');
                lines[1] = "".PadRight(44, '<');
            }

            return lines[0] + "\n" + lines[1];
        }
    }
}
