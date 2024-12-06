using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Resources.Interfaces
{
    public interface INfcReader
    {
        void StartListening();
        void StopListening();
    }
}
