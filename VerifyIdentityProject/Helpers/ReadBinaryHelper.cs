using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    public class ReadBinaryHelper
    {

        private byte[] _ksEnc;
        private byte[] _ksMac;
        private byte[] _ssc;
        private Dictionary<string, string> _dictionaryMrzData;

        //public ReadBinaryHelper(byte[] ksEnc, byte[] ksMac)
        //{
        //    _ksEnc = ksEnc;
        //    _ksMac = ksMac;
        //    _ssc = new byte[16];
        //}

        public void VerifyRapduCCPace(byte[] rapdu, ref byte[] SSC, byte[] ksMac, byte[] ksEnc)
        {
            SecureMessagingHelper secureMessagingHelper = new SecureMessagingHelper(ksEnc, ksMac);
            Console.WriteLine($"rapdu: {BitConverter.ToString(rapdu)}");


            //-----------------------------------------------------------------------ii. Concatenate SSC, DO‘87’ and DO‘99’ and add padding: -extract DO‘87’ and DO‘99’ from RPADU-
            //                                                                          K = ‘88-70-22-12-0C-06-C2-2C-87-19-01-FB-92-35-F4-E4-03-7F-23-27-DC-C8-96-4F-1F-9B-8C-30-F4-2C-8E-2F-FF-22-4A-99-02-90-00’ - Rätt
            //                                                                     Recieved: 88-70-22-12-0C-06-C2-2C-87-19-01-FB-92-35-F4-E4-03-7F-23-27-DC-C8-96-4F-1F-9B-8C-30-F4-2C-8E-2F-FF-22-4A-99-02-90-00
            // 1. Extract DO87 and DO99 from RAPDU
            byte[] do87 = ExtractDO87Pace(rapdu);
            byte[] do99 = ExtractDO99Pace(rapdu);

            Console.WriteLine($"ksMac: {BitConverter.ToString(ksMac)}");
            Console.WriteLine($"DO87: {BitConverter.ToString(do87)}");
            Console.WriteLine($"DO99: {BitConverter.ToString(do99)}");
            Console.WriteLine($"SSC: {BitConverter.ToString(SSC)}");


            // 2. build K SSC, DO‘87’ and DO‘99’ and add padding
            byte[] concatenatedData = do87.Concat(do99).ToArray();
            byte[] k = secureMessagingHelper.PadDataPace(concatenatedData);

            Console.WriteLine($"Concatenated (SSC + DO87 + DO99): {BitConverter.ToString(concatenatedData)}");
            Console.WriteLine($"K (DO87+DO99+pad): {BitConverter.ToString(k)}");

            //-----------------------------------------------------------------------iii. Compute MAC with KSMAC: CC’ = ‘C8-B2-78-7E-AE-A0-7D-74’ - C8-B2-78-7E-AE-A0-7D-74 - Rätt
            byte[] calculatedMacCC = secureMessagingHelper.CalculateMACPace(k, SSC);
            Console.WriteLine($"Calculated MAC -(CC)-: {BitConverter.ToString(calculatedMacCC)}");

            //-----------------------------------------------------------------------iv. Compare CC’ with data of DO‘8E’ of RAPDU ‘C8-B2-78-7E-AE-A0-7D-74’ == ‘C8-B2-78-7E-AE-A0-7D-74’ ? YES. - Rätt
            // 1. Extract DO8E from RAPDU
            byte[] do8e = ExtractDO8E2Pace(rapdu);
            Console.WriteLine($"do8e from RAPDU: {BitConverter.ToString(do8e)}");

            // 2. Extract CC from DO8E in RAPDU
            byte[] ccFromRapdu = do8e.Skip(2).Take(8).ToArray();
            Console.WriteLine($"CC from RAPDU: {BitConverter.ToString(ccFromRapdu)}");

            // 3. Compare CC’ with data of DO‘8E’
            if (calculatedMacCC.SequenceEqual(ccFromRapdu))
            {
                Console.WriteLine("CC verified successfully! MAC matches CC from RAPDU.");
            }
            else
            {
                Console.WriteLine("CC verification failed. Calculated MAC does not match CC from RAPDU.");
            }

        }

        public static byte[] ConstructProtectedAPDUPace(byte[] cmdHeader, byte[] DO97, byte[] DO8E)
        {
            // Lc = Length of DO87 + DO8E
            byte[] shortCmdHeader = cmdHeader.Take(4).ToArray();
            byte lc = (byte)(DO97.Length + DO8E.Length);

            // Bygg Protected APDU
            byte[] protectedAPDU = new byte[shortCmdHeader.Length + 1 + DO97.Length + DO8E.Length + 1];
            Array.Copy(shortCmdHeader, 0, protectedAPDU, 0, shortCmdHeader.Length); // Kopiera CmdHeader
            protectedAPDU[shortCmdHeader.Length] = lc;                        // Lägg till Lc
            Array.Copy(DO97, 0, protectedAPDU, shortCmdHeader.Length + 1, DO97.Length); // Lägg till DO87
            Array.Copy(DO8E, 0, protectedAPDU, shortCmdHeader.Length + 1 + DO97.Length, DO8E.Length); // Lägg till DO8E
            protectedAPDU[^1] = 0x00;                                   // Lägg till Le (0x00)
            //0C-B0-00-00-0D    -97-01-04-  8E-08-  ED-67-05-41-7E-96-BA-55 -00
            //0C-B0-00-00-0D    -97-01-20-  8E-08-  3F-16-75-8A-7A-43-0D-5E -00
            return protectedAPDU;
        }

        public static byte[] ExtractDO87Pace(byte[] rapdu)
        {
            // DO87 startar med taggen 0x87
            int index = Array.IndexOf(rapdu, (byte)0x87);
            if (index == -1) throw new InvalidOperationException("DO87 not found in RAPDU.");

            int length = rapdu[index + 1]; // DO87 längd
            return rapdu.Skip(index).Take(2 + length).ToArray(); // Tag + Längd + Data
        }

        public static byte[] ExtractEncryptedDataFromDO87Pace(byte[] DO87)
        {
            if (DO87[0] != 0x87)
                throw new ArgumentException("Invalid DO‘87’ format");

            int length = DO87[1];
            if (DO87[2] != 0x01) // Förväntar indikator för krypterat data
                throw new ArgumentException("Invalid encrypted data indicator");

            byte[] encryptedData = new byte[length - 1];
            Array.Copy(DO87, 3, encryptedData, 0, encryptedData.Length);
            return encryptedData;
        }

        public static byte[] ExtractDO99Pace(byte[] rapdu)
        {
            // DO99 startar med taggen 0x99
            int index = Array.IndexOf(rapdu, (byte)0x99);
            if (index == -1) throw new InvalidOperationException("DO99 not found in RAPDU.");

            return rapdu.Skip(index).Take(4).ToArray(); // Tag (0x99) + 2 bytes data + 2 bytes SW
        }

        public static byte[] ExtractDO8E2Pace(byte[] rapdu)
        {
            // DO8E startar med taggen 0x8E
            int index = Array.IndexOf(rapdu, (byte)0x8E);
            if (index == -1) throw new InvalidOperationException("DO8E not found in RAPDU.");

            int length = rapdu[index + 1]; // DO8E längd
            return rapdu.Skip(index).Take(2 + length).ToArray(); // Tag + Längd + Data
        }

        //public static Dictionary<string, string> ParseMRZPace(string cleanMRZ)
        //{
        //    // Dela upp MRZ i rader
        //    string[] lines = cleanMRZ.Split('\n');
        //    if (lines.Length < 2) throw new InvalidOperationException("MRZ måste innehålla minst två rader.");

        //    // Extrahera data från första raden
        //    string line1 = lines[0].PadRight(44); // Säkerställ att raden har 44 tecken
        //    string documentType = line1.Substring(0, 1).Trim();
        //    string issuingCountry = line1.Substring(2, 3).Trim();

        //    string namePart = line1.Substring(5);
        //    string[] nameParts = namePart.Split(new string[] { "<<" }, StringSplitOptions.None);

        //    string lastname = nameParts[0].Trim();
        //    string firstnames = nameParts.Length > 1
        //        ? Regex.Replace(nameParts[1], "<", " ").Trim()
        //        : " ";



        //    // Extrahera data från andra raden
        //    string line2 = lines[1].PadRight(44); // Säkerställ att raden har 44 tecken
        //    string passportNumber = line2.Substring(0, 9).Trim();
        //    char passportNumberCheckDigit = line2[9];
        //    string nationality = line2.Substring(10, 3).Trim();
        //    string birthDate = line2.Substring(13, 6).Trim();
        //    char birthDateCheckDigit = line2[19];
        //    string gender = line2.Substring(20, 1).Trim();
        //    string expiryDate = line2.Substring(21, 6).Trim();
        //    char expiryDateCheckDigit = line2[27];
        //    string personalNumber = line2.Substring(28, 14).Trim();
        //    char personalNumberCheckDigit = line2[42];
        //    char finalCheckDigit = line2[43];

        //    // Returnera parsad information
        //    return new Dictionary<string, string>
        //    {
        //        { "Document Type", documentType },
        //        { "Issuing Country", issuingCountry },
        //        { "Last Name", lastname },
        //        { "First Names", firstnames },
        //        { "Passport Number", passportNumber },
        //        { "Passport Number Check Digit", passportNumberCheckDigit.ToString() },
        //        { "Nationality", nationality },
        //        { "Birth Date", birthDate },
        //        { "Birth Date Check Digit", birthDateCheckDigit.ToString() },
        //        { "Gender", gender },
        //        { "Expiry Date", expiryDate },
        //        { "Expiry Date Check Digit", expiryDateCheckDigit.ToString() },
        //        { "Personal Number", personalNumber },
        //        { "Personal Number Check Digit", personalNumberCheckDigit.ToString() },
        //        { "Final Check Digit", finalCheckDigit.ToString() }
        //    };
        //}
    }
}
