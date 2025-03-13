using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    class OidHelper
    {
        // Helper to check if OID starts with a given prefix
        public static bool OidEndsWith(byte[] oidBytes, string suffix)
        {
            string oidString = ConvertOidToString(oidBytes);
            return oidString.EndsWith(suffix);
        }

        // Helper to convert OID bytes to string
        public static string ConvertOidToString(byte[] oidBytes)
        {
            var oid = new List<string>();
            oid.Add((oidBytes[0] / 40).ToString());
            oid.Add((oidBytes[0] % 40).ToString());
            long value = 0;

            for (int i = 1; i < oidBytes.Length; i++)
            {
                value = (value << 7) | (oidBytes[i] & 0x7F);
                if ((oidBytes[i] & 0x80) == 0)
                {
                    oid.Add(value.ToString());
                    value = 0;
                }
            }
            return string.Join(".", oid);
        }
    }
}
