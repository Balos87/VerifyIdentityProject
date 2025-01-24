using System.Threading.Tasks;

namespace VerifyIdentityAPI.Services
{
    public interface IMrzService
    {
        Task<string> ExtractMrzAsync(string imagePath);
    }
}

