using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    public class DebugTextWriter : TextWriter
    {
        private readonly Action<string> _writeAction;

        public DebugTextWriter(Action<string> writeAction)
        {
            _writeAction = writeAction;
        }

        public override Encoding Encoding => Encoding.UTF8;

        public override void Write(string value)
        {
            _writeAction?.Invoke(value);
        }

        public override void WriteLine(string value)
        {
            _writeAction?.Invoke(value);
        }
    }

}
