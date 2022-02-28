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

    [HttpGet("login")]
    public IActionResult Login([FromQuery] string email, [FromQuery] string? role, [FromQuery] bool persist = true)
    {
        var cookie = _tokenService.GenerateCookie(_tokenService.GenerateClaims(email, role));

        var cookieOptions = new CookieOptions()
        {
            Expires = persist ? cookie.Expires : null,
            Path = cookie.Path,
            HttpOnly = cookie.HttpOnly,
            Secure = cookie.Secure,
            SameSite = SameSiteMode.Lax
        };
        Response.Cookies.Append(cookie.Name, cookie.Value, cookieOptions);

        return Ok();
    }

    [Authorize]
    [HttpGet("logout")]
    public IActionResult Logout()
    {
        var cookieOptions = new CookieOptions()
        {
            Expires = DateTime.UnixEpoch,
            Path = "/",
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Lax
        };
        Response.Cookies.Append(CookieConstats.AuthToken, "", cookieOptions);

        return Ok();
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
    [HttpGet("test-auth-admin")]
    public IActionResult TestAdminAuth()
    {
        return Ok(User.Claims.Select(x => new { x.Type, x.Value }));
    }
}
