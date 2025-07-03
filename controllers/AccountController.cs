using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MinhaApiJwt.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AccountsController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;

    public AccountsController(UserManager<ApplicationUser> userManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        var userExists = await _userManager.FindByEmailAsync(dto.Email);
        if (userExists != null)
            return StatusCode(StatusCodes.Status409Conflict, "Usuário já existe.");

        ApplicationUser user = new()
        {
            Email = dto.Email,
            SecurityStamp = Guid.NewGuid().ToString(),
            UserName = dto.Email // UserName é obrigatório
        };

        var result = await _userManager.CreateAsync(user, dto.Password);

        if (!result.Succeeded)
            return StatusCode(StatusCodes.Status500InternalServerError, $"Falha ao criar usuário: {string.Join(", ", result.Errors.Select(e => e.Description))}");

        return Ok("Usuário criado com sucesso!");
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);

        // O segundo parâmetro 'lockoutOnFailure' pode ser usado para bloquear a conta após várias tentativas falhas
        if (user != null && await _userManager.CheckPasswordAsync(user, dto.Password))
        {
            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }

        return Unauthorized("Credenciais inválidas.");
    }

    private string GenerateJwtToken(ApplicationUser user)
    {
        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email ?? ""),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };
        
        // Adicionar roles (funções) se você as estiver usando
        // var userRoles = await _userManager.GetRolesAsync(user);
        // foreach (var role in userRoles) { authClaims.Add(new Claim(ClaimTypes.Role, role)); }

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"] ?? ""));

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddHours(3),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

// Crie os DTOs para receber os dados
public class RegisterDto { public required string Email { get; set; } public required string Password { get; set; } }
public class LoginDto { public required string Email { get; set; } public required string Password { get; set; } }