using Android.Nfc.Tech;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using VerifyIdentityProject.Platforms.Android;
using static Android.Renderscripts.ScriptGroup;

public class SecureMessage
{
    private readonly IsoDep _isoDep;
    private readonly byte[] _ksEnc;
    private readonly byte[] _ksMac;
    private byte[] _ssc;

    public SecureMessage(byte[] ksEnc, byte[] ksMac, IsoDep isoDep)
    {
        _ksEnc = ksEnc;
        _ksMac = ksMac;
        _isoDep = isoDep;
        _ssc = new byte[16];
    }

    public bool PerformSecureMessage()
    {
        Console.WriteLine("-------------------------------------Secure Messaging started..");
        try
        {
            var secureMessage3 = new SecureMessage3(_ksEnc, _ksMac, _isoDep);
            var selectApplication = secureMessage3.SelectApplication();
            var selectDG1 = secureMessage3.SelectDG1();

            //SecureMessageOldBack.SelectApplication(_isoDep, _ksEnc, _ksMac, _ssc);
            //var secureMessage = new SecureMessage2(_ksEnc, _ksMac, _isoDep);
            //bool secureMessageSuccess = secureMessage.PerformSecureMessage();
            //Console.WriteLine(secureMessageSuccess ? "Secure Message succeeded!" : "Secure Message failed");


            return true;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            return false;
        }
    }

}