using System.Net;
using System.Net.Mime;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace JwtToken;

public class EncryptedJwtAuthenticationSchemeOptions : AuthenticationSchemeOptions { }

public class EncryptedJwtAuthenticationHandler : AuthenticationHandler<EncryptedJwtAuthenticationSchemeOptions>
{
    private readonly TokenService _tokenService;

    public EncryptedJwtAuthenticationHandler(
            IOptionsMonitor<EncryptedJwtAuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            TokenService tokenService)
            : base(options, logger, encoder, clock)
    {
        _tokenService = tokenService;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.ContainsKey(CookieConstats.AuthToken)
            || Request.Cookies.Count(cookie => cookie.Key == CookieConstats.AuthToken) > 1)
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        string encryptedToken = Request.Cookies[CookieConstats.AuthToken]!;
        var token = _tokenService.DecodeToken(encryptedToken);

        if (token is null)
            return Task.FromResult(AuthenticateResult.Fail("Invalid token."));

        var claimsIdentity = new ClaimsIdentity(token.Claims, Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(claimsIdentity), Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        Response.ContentType = MediaTypeNames.Application.Json;
        await Response.WriteAsync(JsonSerializer.Serialize(new { Message = "You are not authorized." }));
    }

    protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = (int)HttpStatusCode.Forbidden;
        Response.ContentType = MediaTypeNames.Application.Json;
        await Response.WriteAsync(JsonSerializer.Serialize(new { Message = "You are not authorized to access this resource." }));
    }
}
