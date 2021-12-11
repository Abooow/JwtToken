using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtToken.Controllers;

[Route("api/[controller]")]
[ApiController]
public class IdentityController : ControllerBase
{
    private readonly TokenService _tokenService;

    public IdentityController(TokenService tokenService)
    {
        _tokenService = tokenService;
    }

    [HttpGet]
    public IActionResult SignIn([FromQuery] string email, [FromQuery] string? role)
    {
        string token = _tokenService.GenerateToken(_tokenService.GenerateClaims(email, role));

        return Ok(new { token });
    }

    [HttpGet("test-token")]
    public IActionResult TestToken([FromQuery] string token)
    {
        var securityToken = _tokenService.DecodeToken(token);

        if (securityToken is null)
            return BadRequest("Invalid token.");

        return Ok(securityToken.Claims.Select(x => new { x.Type, x.Value }));
    }

    [Authorize]
    [HttpGet("test-auth")]
    public IActionResult TestAuth()
    {
        return Ok(User.Claims.Select(x => new { x.Type, x.Value }));
    }

    [Authorize(Roles = "Admin")]
    [HttpGet("test-adminauth")]
    public IActionResult TestAdminAuth()
    {
        return Ok(User.Claims.Select(x => new { x.Type, x.Value }));
    }
}
