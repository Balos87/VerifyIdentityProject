
namespace VerifyIdentityAPI.Models
{
    public class Quiz
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public ICollection<User>? User { get; set; }
    }
}
