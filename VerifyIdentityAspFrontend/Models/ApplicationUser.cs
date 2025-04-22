using Microsoft.AspNetCore.Identity;
using System;

namespace VerifyIdentityAspFrontend.Models
{
    public class ApplicationUser : IdentityUser
    {
        public Person? Person { get; set; }
    }
}
