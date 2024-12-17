using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Resources.Interfaces
{
    public interface INfcReaderManager
    {
        void StartListening();
        void StopListening();
    }
}
