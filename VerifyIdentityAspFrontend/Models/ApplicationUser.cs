using Microsoft.AspNetCore.Identity;
using System;

namespace VerifyIdentityAspFrontend.Models
{
    public class ApplicationUser : IdentityUser
    {
        public Person? Person { get; set; }
        public ICollection<VerifyOperation> VerifyOperations { get; set; } = new List<VerifyOperation>();
    }

}