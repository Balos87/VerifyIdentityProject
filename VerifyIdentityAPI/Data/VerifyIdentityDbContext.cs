using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using VerifyIdentityAPI.Models;

namespace VerifyIdentityAPI.Data
{
    public class VerifyIdentityDbContext : IdentityDbContext<User>
    {
        public VerifyIdentityDbContext(DbContextOptions<VerifyIdentityDbContext> options) : base(options) { }

        public DbSet<Quiz> Quizzes { get; set; }

    }
}
