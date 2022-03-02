using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtToken.Controllers;

[Route("api/[controller]")]
[ApiController]
public class IdentityController : ControllerBase
{
    private readonly TokenService _tokenService;
    private readonly CookieService _cookieService;
    private readonly RefreshTokenRepository _refreshTokenRepository;

    public IdentityController(TokenService tokenService, CookieService cookieService, RefreshTokenRepository refreshTokenRepository)
    {
        _tokenService = tokenService;
        _cookieService = cookieService;
        _refreshTokenRepository = refreshTokenRepository;
    }

    [HttpGet("login")]
    public IActionResult Login([FromQuery] string email, [FromQuery] string? role, [FromQuery] bool persist = true)
    {
        string? existingJtiToken = User.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)?.Value;
        if (existingJtiToken is not null)
            _refreshTokenRepository.InvalidateToken(existingJtiToken);

        var claims = _tokenService.GenerateClaims(email, role);
        (string token, _) = _tokenService.GenerateToken(claims);

        string userId = email;
        string jti = claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
        RefreshToken refreshToken = _refreshTokenRepository.CreateNewRefreshToken(userId, jti, persist);

        DateTime? expireCookieTime = persist ? refreshToken!.Expires : null;
        _cookieService.SetCookie(CookieConstats.AuthToken, token, expireCookieTime);
        _cookieService.SetCookie(CookieConstats.RefreshToken, refreshToken.Token, expireCookieTime);

        return Ok();
    }

    [Authorize]
    [HttpGet("logout")]
    public IActionResult Logout()
    {
        string existingJtiToken = User.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)!.Value;
        _refreshTokenRepository.InvalidateToken(existingJtiToken);

        _cookieService.SetCookie(CookieConstats.AuthToken, "", DateTime.UnixEpoch);
        _cookieService.SetCookie(CookieConstats.RefreshToken, "", DateTime.UnixEpoch);

        return Ok();
    }

    [Authorize]
    [HttpGet("refresh-tokens")]
    public IActionResult GetRefreshTokens() // For testing.
    {
        string userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var refreshTokens = _refreshTokenRepository.GetRefreshTokens(userId);

        return Ok(refreshTokens.OrderBy(x => x.Expires).Select(x => new { x.Token, x.Expires, x.Invalidated }));
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
