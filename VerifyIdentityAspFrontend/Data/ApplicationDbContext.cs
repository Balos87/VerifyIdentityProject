using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using VerifyIdentityAspFrontend.Models;

namespace VerifyIdentityAspFrontend.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<Person> People { get; set; }
        public DbSet<VerifyOperation> VerifyOperations { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // 1:1 Person ↔ User
            builder.Entity<Person>()
                   .HasOne(p => p.User)
                   .WithOne(u => u.Person)
                   .HasForeignKey<Person>(p => p.UserId)
                   .OnDelete(DeleteBehavior.Cascade);

            // 1:N VerifyOperation ↔ User
            builder.Entity<VerifyOperation>()
                   .HasOne(op => op.User)           // each op has one User
                   .WithMany(u => u.VerifyOperations) // one user can have many ops
                   .HasForeignKey(op => op.UserId)  // the FK prop
                   .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
