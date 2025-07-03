using Microsoft.AspNetCore.Identity;

namespace MinhaApiJwt.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? NomeCompleto { get; set; }
    }
}