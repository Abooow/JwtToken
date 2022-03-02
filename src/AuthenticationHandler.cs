using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace JwtToken;

public class AuthenticationSchemeOptions : Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions { }

public class AuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly TokenService _tokenService;
    private readonly RefreshTokenRepository _refreshTokenRepository;
    private readonly CookieService _cookieService;

    public AuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            TokenService tokenService,
            RefreshTokenRepository refreshTokenRepository,
            CookieService cookieService)
            : base(options, logger, encoder, clock)
    {
        _tokenService = tokenService;
        _refreshTokenRepository = refreshTokenRepository;
        _cookieService = cookieService;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!_cookieService.ContainsSingleCookie(CookieConstats.AuthToken))
            return Task.FromResult(AuthenticateResult.NoResult());

        string tokenCookie = _cookieService.GetCookie(CookieConstats.AuthToken)!;

        // Validate access token.
        var token = _tokenService.DecodeToken(tokenCookie);
        if (token is null)
            return Task.FromResult(AuthenticateResult.Fail("Invalid token."));

        // Get expiry date of access token.
        long expiryDateUnix = long.Parse(token.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
        var expiryDateTime = DateTime.UnixEpoch.AddSeconds(expiryDateUnix);

        // If not expired - grant access.
        if (expiryDateTime > DateTime.UtcNow)
        {
            var claimsIdentity1 = new ClaimsIdentity(token.Claims, Scheme.Name);
            var ticket1 = new AuthenticationTicket(new ClaimsPrincipal(claimsIdentity1), Scheme.Name);

            return Task.FromResult(AuthenticateResult.Success(ticket1));
        }

        // Token has expired - create new access token and refresh token using the current refresh token.

        if (!_cookieService.ContainsSingleCookie(CookieConstats.RefreshToken))
            return Task.FromResult(AuthenticateResult.NoResult());

        string refreshTokenCookie = _cookieService.GetCookie(CookieConstats.RefreshToken)!;

        string jwtId = token.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
        var refreshToken = _refreshTokenRepository.GetRefreshToken(refreshTokenCookie);

        if (refreshToken is null)
            return Task.FromResult(AuthenticateResult.Fail("Invalid refresh token."));

        if (refreshToken.Invalidated)
        {
            // WARNING: Suspicious behavior detected - User is trying to use an old refresh token!
            return Task.FromResult(AuthenticateResult.Fail("Invalid refresh token."));
        }

        // Ensure the refresh token is valid for the current access token.
        if (refreshToken.JwtId != jwtId)
            return Task.FromResult(AuthenticateResult.Fail("Invalid refresh token."));

        // Invalidate old refresh token.
        _refreshTokenRepository.InvalidateToken(refreshTokenCookie);

        // Create new access token and refresh token.
        var newClaims = _tokenService.CopyClaims(token); // Same claims but new JWT Id.
        string newJwtId = newClaims.Single(x => x.Type == JwtRegisteredClaimNames.Jti).Value;
        string userId = newClaims.Single(x => x.Type == ClaimTypes.NameIdentifier).Value;

        var newAccessToken = _tokenService.GenerateToken(newClaims);
        var newRefreshToken = _refreshTokenRepository.CreateNewRefreshToken(userId, newJwtId, refreshToken.Persist);

        // Override tokens.
        _cookieService.SetCookie(CookieConstats.AuthToken, newAccessToken.Token, newRefreshToken.Persist ? newRefreshToken.Expires : null);
        _cookieService.SetCookie(CookieConstats.RefreshToken, newRefreshToken.Token, newRefreshToken.Persist ? newRefreshToken.Expires : null);

        var claimsIdentity = new ClaimsIdentity(newAccessToken.Claims, Scheme.Name);
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(claimsIdentity), Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = (int)HttpStatusCode.Unauthorized;

        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = (int)HttpStatusCode.Forbidden;

        return Task.CompletedTask;
    }
}
