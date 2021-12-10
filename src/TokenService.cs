using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtToken;

public class TokenService
{
    private readonly JwtSettings _jwtSettings;

    public TokenService(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    public string GenerateToken(IEnumerable<Claim> claims)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            _jwtSettings.Issuer,
            _jwtSettings.Issuer,
            claims,
            expires: DateTime.UtcNow.Add(_jwtSettings.ExpirationTime),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public JwtSecurityToken? DecodeToken(string token)
    {
        return ValidateToken(token) ? new JwtSecurityTokenHandler().ReadJwtToken(token) : null;
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

    public IEnumerable<Claim> GenerateClaims(string userId, string email)
    {
        return new Claim[]
        {
            new (JwtRegisteredClaimNames.NameId, userId),
            new (JwtRegisteredClaimNames.Email, email),
            new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
    }
}
