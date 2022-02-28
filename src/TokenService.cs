using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JwtToken;

public class TokenService
{
    private readonly JwtSettings _jwtSettings;

    public TokenService(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    public Cookie GenerateCookie(IEnumerable<Claim> claims)
    {
        var expires = DateTime.UtcNow.Add(_jwtSettings.ExpirationTime);
        string token = GenerateToken(claims, expires);

        return new Cookie()
        {
            Name = CookieConstats.AuthToken,
            Value = token,
            Expires = expires,
            Path = "/",
            HttpOnly = true,
            Secure = true,
        };
    }

    public string GenerateToken(IEnumerable<Claim> claims)
    {
        return GenerateToken(claims, DateTime.UtcNow.Add(_jwtSettings.ExpirationTime));
    }

    public JwtSecurityToken? DecodeToken(string token)
    {
        return ValidateToken(token) ? new JwtSecurityTokenHandler().ReadJwtToken(token) : null;
    }

    private string GenerateToken(IEnumerable<Claim> claims, DateTime expires)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            _jwtSettings.Issuer,
            _jwtSettings.Issuer,
            claims,
            notBefore: null,
            expires,
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private bool ValidateToken(string token)
    {
        var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.Key));

        var tokenHandler = new JwtSecurityTokenHandler();
        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidAudience = _jwtSettings.Issuer,
                IssuerSigningKey = mySecurityKey
            }, out SecurityToken validatedToken);
        }
        catch
        {
            return false;
        }

        return true;
    }

    public IEnumerable<Claim> GenerateClaims(string email, string? role)
    {
        return new Claim[]
        {
            new (JwtRegisteredClaimNames.Email, email),
            new (ClaimsIdentity.DefaultRoleClaimType, role ?? "None"),
            new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
    }
}
