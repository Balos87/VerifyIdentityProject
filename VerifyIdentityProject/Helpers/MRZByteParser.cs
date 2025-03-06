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

                // Börja läsa efter vi hittar 'P' eller '<'
                if (!startedReading && (b == 0x50 || b == 0x3C))
                {
                    startedReading = true;
                }

                if (startedReading)
                {
                    // Inkludera bara giltiga MRZ-tecken
                    if ((b >= 0x30 && b <= 0x39) ||  // Siffror
                        (b >= 0x41 && b <= 0x5A) ||  // Stora bokstäver
                        b == 0x3C)                   // < tecken
                    {
                        mrz.Append((char)b);
                    }
                }
            }

            string result = mrz.ToString();

            // Säkerställ att resultatet har korrekt längd för MRZ (44 tecken per rad)
            if (result.Length >= 88)
            {
                return result.Substring(0, 88);
            }

            // Fyll ut med < tecken om det behövs
            return result.PadRight(88, '<');
        }

        public static string FormatMRZForBAC(string mrz)
        {
            // Säkerställ att vi har exakt två rader med 44 tecken var
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

        public static (string DocumentNumber, string DateOfBirth, string DateOfExpiry) ExtractBACElements(string mrz)
        {
            // Extrahera relevanta delar för BAC
            string documentNumber = "";
            string dateOfBirth = "";
            string dateOfExpiry = "";

            try
            {
                // Dokumentnummer finns vanligtvis i andra raden
                string[] lines = mrz.Split('\n');
                if (lines.Length >= 2)
                {
                    documentNumber = lines[1].Substring(0, 9).Trim('<');
                    dateOfBirth = lines[1].Substring(13, 6);
                    dateOfExpiry = lines[1].Substring(21, 6);
                }
            }
            catch
            {
                // Vid fel, returnera tomma strängar
            }

            return (documentNumber, dateOfBirth, dateOfExpiry);
        }
    }
}
