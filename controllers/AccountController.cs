using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MinhaApiJwt.Models;
using MinhaApiJwt.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[ApiController]
[Route("api/[controller]")]
public class AccountsController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly EmailService _emailService;

    public AccountsController(UserManager<ApplicationUser> userManager, IConfiguration configuration, EmailService emailService)
    {
        _userManager = userManager;
        _configuration = configuration;
        _emailService = emailService;
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
            UserName = dto.UserName
        };

        var result = await _userManager.CreateAsync(user, dto.Password);

        if (!result.Succeeded)
            return StatusCode(StatusCodes.Status500InternalServerError, $"Falha ao criar usuário: {string.Join(", ", result.Errors.Select(e => e.Description))}");

        await _userManager.AddToRoleAsync(user, "User");
        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = Url.Action("ConfirmEmail", "Accounts",
                new { userId = user.Id, token }, protocol: Request.Scheme);

        await _emailService.sendEmailAsync(dto.Email, "Confirme seu e-mail", $"Por favor, confirme sua conta <a href='{callbackUrl}'>clicando aqui</a>.", cancellationToken: default);
        return Ok($"Usuário criado com sucesso! Url de confirmação: {callbackUrl}");
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

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ?? ""));

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            expires: DateTime.Now.AddHours(3),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    [HttpGet]
    public async Task<IActionResult> ConfirmEmail(string userId, string token)
    {
        if (userId == null || token == null)
        {
            return NotFound();
        }

        var user = await _userManager.FindByIdAsync(userId);

        if (user == null)
        {
            return NotFound($"Não foi possível encontrar o usuário com o ID '{userId}'.");
        }

        var result = await _userManager.ConfirmEmailAsync(user, token);
        if (result.Succeeded)
        {
            return Ok("Email confirmado com sucesso");
        }

        return BadRequest();
    }
}

// Crie os DTOs para receber os dados
public class RegisterDto { public required string Email { get; set; } public required string UserName { get; set; } public required string Password { get; set; } }
public class LoginDto { public required string Email { get; set; } public required string Password { get; set; } }