using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.Extensions.Options;

namespace JwtToken;

public class RefreshTokenRepository
{
    // Only for testing. The refresh tokens should be stored in a database.
    private static readonly ConcurrentDictionary<string, RefreshToken> refreshTokens = new(); // Key = Refresh token.

    private readonly JwtSettings _jwtSettings;

    public RefreshTokenRepository(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    public RefreshToken? GetRefreshToken(string token)
    {
        refreshTokens.TryGetValue(token, out var refreshToken);
        return refreshToken;
    }

    public RefreshToken CreateNewRefreshToken(string jwtId)
    {
        var expires = DateTime.UtcNow.Add(_jwtSettings.RefreshTokenExpirationTime);
        var refreshToken = new RefreshToken(Guid.NewGuid().ToString(), jwtId, expires, false);

        refreshTokens.TryAdd(refreshToken.Token, refreshToken);

        return refreshToken;
    }

    public void InvalidateToken(string token)
    {
        if (refreshTokens.TryGetValue(token, out var refreshToken))
            refreshTokens.TryUpdate(token, refreshToken with { Invalidated = true }, refreshToken);
    }
}

public record RefreshToken(string Token, string JwtId, DateTime Expires, bool Invalidated);
