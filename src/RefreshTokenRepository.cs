using System.Collections.Concurrent;
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

    public RefreshToken CreateNewRefreshToken(string userId, string jwtId, bool persist)
    {
        var expires = DateTime.UtcNow.Add(_jwtSettings.RefreshTokenExpirationTime);
        var refreshToken = new RefreshToken(Guid.NewGuid().ToString(), userId, jwtId, expires, false, persist);

        refreshTokens.TryAdd(refreshToken.Token, refreshToken);

        return refreshToken;
    }

    public void InvalidateToken(string token)
    {
        if (refreshTokens.TryGetValue(token, out var refreshToken))
            refreshTokens.TryUpdate(token, refreshToken with { Invalidated = true }, refreshToken);
    }

    // For testing.
    public IEnumerable<RefreshToken> GetRefreshTokens(string userId)
    {
        return refreshTokens.Values.Where(x => x.UserId == userId);
    }
}

public record RefreshToken(string Token, string UserId, string JwtId, DateTime Expires, bool Invalidated, bool Persist);
