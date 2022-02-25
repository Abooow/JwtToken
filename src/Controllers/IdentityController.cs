﻿using Microsoft.AspNetCore.Authorization;
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
    public IActionResult SignIn([FromQuery] string email)
    {
        var cookie = _tokenService.GenerateCookie(_tokenService.GenerateClaims(email.GetHashCode().ToString(), email));

        var cookieOptions = new CookieOptions()
        {
            Expires = cookie.Expires,
            Path = cookie.Path,
            Domain = cookie.Domain,
            HttpOnly = cookie.HttpOnly,
            Secure = cookie.Secure
        };
        Response.Cookies.Append(cookie.Name, cookie.Value);

        return Ok(new { Token = cookie.Value });
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
}
