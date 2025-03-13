using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace VerifyIdentityProject.Helpers
{
    // Custom exceptions for pace
    public class PaceException : Exception
    {
        public PaceException(string message) : base(message) { }
        public PaceException(string message, Exception inner) : base(message, inner) { }
    }
}
