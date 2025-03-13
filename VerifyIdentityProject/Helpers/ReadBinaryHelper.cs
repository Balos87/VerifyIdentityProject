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
        public void VerifyRapduCCPace(byte[] rapdu, ref byte[] SSC, byte[] ksMac, byte[] ksEnc)
        {
            SecureMessagingHelper secureMessagingHelper = new SecureMessagingHelper(ksEnc, ksMac);
            // Console.WriteLine($"rapdu: {BitConverter.ToString(rapdu)}");


            //-----------------------------------------------------------------------ii. Concatenate SSC, DO‘87’ and DO‘99’ and add padding: -extract DO‘87’ and DO‘99’ from RPADU-
            //                                                                          K = ‘88-70-22-12-0C-06-C2-2C-87-19-01-FB-92-35-F4-E4-03-7F-23-27-DC-C8-96-4F-1F-9B-8C-30-F4-2C-8E-2F-FF-22-4A-99-02-90-00’ - ✅
            //                                                                     Recieved: 88-70-22-12-0C-06-C2-2C-87-19-01-FB-92-35-F4-E4-03-7F-23-27-DC-C8-96-4F-1F-9B-8C-30-F4-2C-8E-2F-FF-22-4A-99-02-90-00
            // 1. Extract DO87 and DO99 from RAPDU
            byte[] do87 = ExtractDO87Pace(rapdu);
            byte[] do99 = ExtractDO99Pace(rapdu);

            //  Console.WriteLine($"ksMac: {BitConverter.ToString(ksMac)}");
            //  Console.WriteLine($"DO87: {BitConverter.ToString(do87)}");
            //  Console.WriteLine($"DO99: {BitConverter.ToString(do99)}");
            //  Console.WriteLine($"SSC: {BitConverter.ToString(SSC)}");


            // 2. build K SSC, DO‘87’ and DO‘99’ and add padding
            byte[] concatenatedData = do87.Concat(do99).ToArray();
            byte[] k = secureMessagingHelper.PadDataPace(concatenatedData);

            //  Console.WriteLine($"Concatenated (SSC + DO87 + DO99): {BitConverter.ToString(concatenatedData)}");
            //  Console.WriteLine($"K (DO87+DO99+pad): {BitConverter.ToString(k)}");

            //-----------------------------------------------------------------------iii. Compute MAC with KSMAC: CC’ = ‘C8-B2-78-7E-AE-A0-7D-74’ - C8-B2-78-7E-AE-A0-7D-74 - ✅
            byte[] calculatedMacCC = secureMessagingHelper.CalculateMACPace(k, SSC);
            //  Console.WriteLine($"Calculated MAC -(CC)-: {BitConverter.ToString(calculatedMacCC)}");

            //-----------------------------------------------------------------------iv. Compare CC’ with data of DO‘8E’ of RAPDU ‘C8-B2-78-7E-AE-A0-7D-74’ == ‘C8-B2-78-7E-AE-A0-7D-74’ ? YES. - ✅
            // 1. Extract DO8E from RAPDU
            byte[] do8e = ExtractDO8E2Pace(rapdu);
            //  Console.WriteLine($"do8e from RAPDU: {BitConverter.ToString(do8e)}");

            // 2. Extract CC from DO8E in RAPDU
            byte[] ccFromRapdu = do8e.Skip(2).Take(8).ToArray();
            //  Console.WriteLine($"CC from RAPDU: {BitConverter.ToString(ccFromRapdu)}");

            // 3. Compare CC’ with data of DO‘8E’
            if (calculatedMacCC.SequenceEqual(ccFromRapdu))
            {
                // Console.WriteLine("CC verified successfully! MAC matches CC from RAPDU.");
            }
            else
            {
                //  Console.WriteLine("CC verification failed. Calculated MAC does not match CC from RAPDU.");
            }
        }

        public static byte[] ConstructProtectedAPDUPace(byte[] cmdHeader, byte[] DO97, byte[] DO8E)
        {
            // Lc = Length of DO87 + DO8E
            byte[] shortCmdHeader = cmdHeader.Take(4).ToArray();
            byte lc = (byte)(DO97.Length + DO8E.Length);

            // build Protected APDU
            byte[] protectedAPDU = new byte[shortCmdHeader.Length + 1 + DO97.Length + DO8E.Length + 1];
            Array.Copy(shortCmdHeader, 0, protectedAPDU, 0, shortCmdHeader.Length); // copy CmdHeader
            protectedAPDU[shortCmdHeader.Length] = lc;                        // Add Lc
            Array.Copy(DO97, 0, protectedAPDU, shortCmdHeader.Length + 1, DO97.Length); // Add DO87
            Array.Copy(DO8E, 0, protectedAPDU, shortCmdHeader.Length + 1 + DO97.Length, DO8E.Length); // Add DO8E
            protectedAPDU[^1] = 0x00;                                   // Add Le (0x00)

            return protectedAPDU;
        }

        public static byte[] ExtractDO87Pace(byte[] rapdu)
        {
            // DO87 starts with 0x87
            int index = Array.IndexOf(rapdu, (byte)0x87);
            if (index == -1) throw new InvalidOperationException("DO87 not found in RAPDU.");

            int length = rapdu[index + 1]; // DO87 Length
            return rapdu.Skip(index).Take(2 + length).ToArray(); // returns Tag + Length + Data
        }

        public static byte[] ExtractEncryptedDataFromDO87Pace(byte[] DO87)
        {
            if (DO87[0] != 0x87)
                throw new ArgumentException("Invalid DO‘87’ format");

            int length = DO87[1];
            if (DO87[2] != 0x01) // Expecting indicator for encrypted data
                throw new ArgumentException("Invalid encrypted data indicator");

            byte[] encryptedData = new byte[length - 1];
            Array.Copy(DO87, 3, encryptedData, 0, encryptedData.Length);
            return encryptedData;
        }

        public static byte[] ExtractDO99Pace(byte[] rapdu)
        {
            // DO99 starts with 0x99
            int index = Array.IndexOf(rapdu, (byte)0x99);
            if (index == -1) throw new InvalidOperationException("DO99 not found in RAPDU.");

            return rapdu.Skip(index).Take(4).ToArray(); // returns Tag (0x99) + 2 bytes data + 2 bytes SW
        }

        public static byte[] ExtractDO8E2Pace(byte[] rapdu)
        {
            // DO8E starts with 0x8E
            int index = Array.IndexOf(rapdu, (byte)0x8E);
            if (index == -1) throw new InvalidOperationException("DO8E not found in RAPDU.");

            int length = rapdu[index + 1]; // DO8E Length
            return rapdu.Skip(index).Take(2 + length).ToArray(); // returns Tag + Length + Data
        }
    }
}
