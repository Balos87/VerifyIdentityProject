using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using VerifyIdentityAspFrontend.Data;

namespace VerifyIdentityAspFrontend
{
    public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();

            // Use your real connection string here
            optionsBuilder.UseSqlServer("Server=(localdb)\\mssqllocaldb;Database=aspnet-VerifyIdentityAspFrontend-3c735e9e-e372-4916-8ac8-509b97917b91;Trusted_Connection=True;MultipleActiveResultSets=true");

            return new ApplicationDbContext(optionsBuilder.Options);
        }
    }
}
