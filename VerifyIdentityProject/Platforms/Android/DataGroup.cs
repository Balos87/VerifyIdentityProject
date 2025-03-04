using Android.Nfc.Tech;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public abstract class DataGroup
    {
        public byte[] RawData { get; private set; }
        public DataGroup(byte[] data)
        {
            RawData = data;
        }

        public abstract DataGroupId DataGroupType { get; }
    }

    public enum DataGroupId
    {
        COM,
        DG1,
        // Add other data group types (DG1, DG2, etc.) as needed
    }

    public class COM : DataGroup
    {
        public string Version { get; private set; } = "Unknown";
        public string UnicodeVersion { get; private set; } = "Unknown";
        public List<string> DataGroupsPresent { get; private set; } = new List<string>();

        public override DataGroupId DataGroupType => DataGroupId.COM;
        /// <summary>
        /// Selects the file for the given DataGroupId using the ISO-DEP interface.
        /// Logs the APDU and the response.
        /// </summary>
        public static async Task<bool> SelectFile(IsoDep isoDep, DataGroupId dg)
        {
            byte[] fileId = GetFileId(dg);
            if (fileId == null)
                throw new Exception("File identifier not defined for " + dg.ToString());

            byte[] selectApdu = BuildSelectFileApdu(fileId);
            Console.WriteLine("[SELECT] Sending APDU: " + BitConverter.ToString(selectApdu));
            byte[] response = await isoDep.TransceiveAsync(selectApdu);
            Console.WriteLine("[SELECT] Received response: " + BitConverter.ToString(response));

            // A successful response ends with 0x90 0x00
            bool success = response.Length >= 2 &&
                           response[response.Length - 2] == 0x90 &&
                           response[response.Length - 1] == 0x00;
            if (success)
                Console.WriteLine("[SELECT] File selected successfully.");
            else
                Console.WriteLine("[SELECT] Failed to select file.");
            return success;
        }

        /// <summary>
        /// Builds a SELECT FILE APDU given a file identifier.
        /// </summary>
        private static byte[] BuildSelectFileApdu(byte[] fileId)
        {
            // SELECT FILE APDU:
            // CLA: 0x00, INS: 0xA4, P1: 0x02, P2: 0x0C, Lc: fileId length, fileId, Le: 0x00.
            byte[] header = new byte[] { 0x00, 0xA4, 0x02, 0x0C, (byte)fileId.Length };
            return header.Concat(fileId).Concat(new byte[] { 0x00 }).ToArray();
        }

        /// <summary>
        /// Returns the file identifier for a given DataGroupId.
        /// For COM, the file identifier is typically [0x01, 0x1E].
        /// </summary>
        private static byte[] GetFileId(DataGroupId dg)
        {
            switch (dg)
            {
                case DataGroupId.COM:
                    return new byte[] { 0x01, 0x1E };
                // Add other cases for DG1, DG2, etc. as needed.
                default:
                    return null;
            }
        }
    
        public COM(byte[] data) : base(data)
        {
            // Check if the outer envelope tag is present (0x60 for COM)
            if (data.Length > 0 && data[0] == 0x60)
            {
                // Read the length from the next byte (this is simplified; real implementations may use multi-byte lengths)
                int envelopeLength = data[1];
                // Extract the inner data. The inner data starts at offset 2.
                byte[] innerData = new byte[envelopeLength];
                Array.Copy(data, 2, innerData, 0, envelopeLength);
                data = innerData;
            }
            Parse(data);
        }



        public void Parse(byte[] data)
        {
            TLVParser parser = new TLVParser(data);

            // Expect first tag to be 0x5F01 (version)
            byte tag = parser.GetNextTag();
            if (tag != 0x5F01)
                throw new Exception("Expected tag 0x5F01 for version");
            byte[] versionBytes = parser.GetNextValue();
            if (versionBytes.Length == 4)
            {
                // Convert 2 bytes each to string and then to integer
                string majorStr = Encoding.ASCII.GetString(versionBytes, 0, 2);
                string minorStr = Encoding.ASCII.GetString(versionBytes, 2, 2);
                if (int.TryParse(majorStr, out int major) && int.TryParse(minorStr, out int minor))
                    Version = $"{major}.{minor}";
            }

            // Expect next tag to be 0x5F36 (Unicode version)
            tag = parser.GetNextTag();
            if (tag != 0x5F36)
                throw new Exception("Expected tag 0x5F36 for Unicode version");
            byte[] unicodeBytes = parser.GetNextValue();
            if (unicodeBytes.Length == 6)
            {
                string majorStr = Encoding.ASCII.GetString(unicodeBytes, 0, 2);
                string minorStr = Encoding.ASCII.GetString(unicodeBytes, 2, 2);
                string patchStr = Encoding.ASCII.GetString(unicodeBytes, 4, 2);
                if (int.TryParse(majorStr, out int major) &&
                    int.TryParse(minorStr, out int minor) &&
                    int.TryParse(patchStr, out int patch))
                    UnicodeVersion = $"{major}.{minor}.{patch}";
            }

            // Expect next tag to be 0x5C (data groups present)
            tag = parser.GetNextTag();
            if (tag != 0x5C)
                throw new Exception("Expected tag 0x5C for data groups present");
            byte[] dgList = parser.GetNextValue();
            foreach (byte dg in dgList)
            {
                DataGroupsPresent.Add(MapDataGroupTagToName(dg));
            }
        }

        private string MapDataGroupTagToName(byte tag)
        {
            // Example mapping – adjust according to your needs.
            // Typically, 0x01 -> "DG1", 0x02 -> "DG2", etc.
            switch (tag)
            {
                case 0x01: return "DG1";
                case 0x02: return "DG2";
                case 0x03: return "DG3";
                // ... add additional mappings as needed.
                default: return $"Unknown(0x{tag:X2})";
            }
        }
    }

    // A simple TLV parser for demonstration purposes.
    public class TLVParser
    {
        private readonly byte[] data;
        private int position;

        public TLVParser(byte[] data)
        {
            this.data = data;
            this.position = 0;
        }

        public byte GetNextTag()
        {
            if (position >= data.Length)
                throw new Exception("No more data for tag");
            return data[position++];
        }

        public byte[] GetNextValue()
        {
            if (position >= data.Length)
                throw new Exception("No more data for length");
            // For simplicity, assume length is encoded in one byte
            int length = data[position++];
            if (position + length > data.Length)
                throw new Exception("Value length exceeds available data");
            byte[] value = new byte[length];
            Array.Copy(data, position, value, 0, length);
            position += length;
            return value;
        }
    }
    public class DG1 : DataGroup
    {
        public override DataGroupId DataGroupType => DataGroupId.DG1;
        public string MRZData { get; private set; } = "Unknown";

        public DG1(byte[] data) : base(data)
        {
            Parse(data);
        }

        private void Parse(byte[] data)
        {
            // In a real implementation, you would parse the TLV structure according to ICAO LDS.
            // For this example, we assume the entire data is the MRZ in ASCII.
            MRZData = Encoding.ASCII.GetString(data);
        }

        /// <summary>
        /// Returns the file identifier for DG1.
        /// According to LDS, DG1 is typically identified by [0x01, 0x01].
        /// </summary>
        public static byte[] GetFileId()
        {
            return new byte[] { 0x01, 0x01 };
        }

        /// <summary>
        /// Sends a protected SELECT FILE APDU for DG1.
        /// Expected test APDU (hex format):
        ///   0C A4 02 0C 15 87 09 01 <cryptogram> 8E 08 <checksum> 00
        /// </summary>
        public static async Task<bool> SelectFile(IsoDep isoDep, SecureMessaging secureMessaging)
        {
            byte[] fileId = GetFileId();
            // Build the SELECT command header with masked CLA:
            // For secure messaging, use 0x0C as CLA.
            byte[] selectHeader = new byte[] { 0x0C, 0xA4, 0x02, 0x0C };
            // Use the fileId as the data field.
            byte[] dataField = fileId;
            // For SELECT, we typically omit Le, so pass null.
            byte[] le = null;

            // Protect the command using secure messaging.
            byte[] protectedApdu = secureMessaging.ProtectCommand(selectHeader, dataField, le);
            Console.WriteLine("[SELECT-DG1] Sending APDU: " + BitConverter.ToString(protectedApdu));
            byte[] response = await isoDep.TransceiveAsync(protectedApdu);
            Console.WriteLine("[SELECT-DG1] Received response: " + BitConverter.ToString(response));

            // A successful SELECT should end with SW 90 00.
            bool success = response.Length >= 2 &&
                           response[response.Length - 2] == 0x90 &&
                           response[response.Length - 1] == 0x00;
            if (success)
                Console.WriteLine("[SELECT-DG1] DG1 selected successfully.");
            else
                Console.WriteLine("[SELECT-DG1] Failed to select DG1. SW: " + BitConverter.ToString(response.Skip(response.Length - 2).ToArray()));
            return success;
        }

        /// <summary>
        /// Sends a protected READ BINARY APDU for DG1.
        /// Expected test APDU (hex format):
        ///   0C B0 00 00 0D 97 01 01 8E 08 <checksum> 00
        /// </summary>
        public static async Task<byte[]> ReadFile(IsoDep isoDep, SecureMessaging secureMessaging)
        {
            // Build the READ BINARY command header:
            // CLA = 0x0C, INS = 0xB0, P1 = 0x00, P2 = 0x00.
            byte[] readHeader = new byte[] { 0x0C, 0xB0, 0x00, 0x00 };
            // For the test scenario, the expected Le (in DO97) is 0x01.
            byte[] le = new byte[] { 0x01 };

            // Protect the READ command.
            byte[] protectedApdu = secureMessaging.ProtectCommand(readHeader, null, le);
            Console.WriteLine("[READ-DG1] Sending APDU: " + BitConverter.ToString(protectedApdu));
            byte[] response = await isoDep.TransceiveAsync(protectedApdu);
            Console.WriteLine("[READ-DG1] Received response: " + BitConverter.ToString(response));

            // Unprotect the response to obtain the clear DG1 data.
            byte[] dg1Data = secureMessaging.UnprotectResponse(response);
            Console.WriteLine("[READ-DG1] Decrypted DG1 Data: " + BitConverter.ToString(dg1Data));
            return dg1Data;
        }
    }
}