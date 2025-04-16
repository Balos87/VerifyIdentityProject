using Microsoft.AspNetCore.Identity;
using System;

namespace VerifyIdentityAspFrontend.Models
{
    public class ApplicationUser : IdentityUser
    {
        // Optional: navigation property to Person
        public Person? Person { get; set; }
    }
}
