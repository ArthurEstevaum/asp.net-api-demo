using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class DataController : ControllerBase
{
  [HttpGet]
  [Authorize]
  public IActionResult Get()
  {
    var nomeDoUsuario = User.Identity?.Name;

    //return Ok($"Olá, {nomeDoUsuario}! Você está autenticado. Aqui estão seus dados secretos.");
    return Ok(User.Identity?.Name);
  }
}