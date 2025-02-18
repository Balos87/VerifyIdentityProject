using Android.Nfc.Tech;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Platforms.Android
{
    public class SecureMessage
    {
        private readonly IsoDep _isoDep;
        private byte[] _ksEnc;
        private byte[] _ksMac;
        public SecureMessage(byte[] ksEnc, byte[] ksMac, IsoDep isoDep)
        {
            _ksEnc = ksEnc;
            _ksMac = ksMac;
            _isoDep = isoDep;
        }

        public bool PerformSecureMessage()
        {

            return true;
        }

    }
}
