using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System.Net;
using System.Net.Mime;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;

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
        if (!Request.Headers.ContainsKey(HeaderNames.Authorization))
            return Task.FromResult(AuthenticateResult.NoResult());

        string authorizationHeader = Request.Headers[HeaderNames.Authorization].ToString();

        if (!authorizationHeader.StartsWith($"{Constants.AuthenticationScheme} "))
            return Task.FromResult(AuthenticateResult.NoResult());

        string encodedToken = authorizationHeader[(Constants.AuthenticationScheme.Length + 1)..];

        var token = _tokenService.DecodeToken(encodedToken);

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
        Response.StatusCode = (int)HttpStatusCode.Unauthorized;
        Response.ContentType = MediaTypeNames.Application.Json;
        await Response.WriteAsync(JsonSerializer.Serialize(new { Message = "You are not authorized to access this resource." }));
    }
}
