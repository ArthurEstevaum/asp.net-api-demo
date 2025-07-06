using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
  [HttpGet("public")]
  public IActionResult GetPublicData()
  {
    return Ok("Estes são dados públicos");
  }

  [HttpGet("protected")]
  [Authorize]
  public IActionResult GetProtectedData()
  {
    var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
    var userEmail = User.FindFirstValue(ClaimTypes.Email);

    return Ok($"Estes são dados protegidos. Você está logado como {userEmail} (id: {userId})");
  }
}