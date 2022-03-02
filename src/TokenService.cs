using System.IdentityModel.Tokens.Jwt;
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

    public (string Token, IEnumerable<Claim> Claims) GenerateToken(IEnumerable<Claim> claims)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            _jwtSettings.Issuer,
            _jwtSettings.Audience,
            claims,
            notBefore: null,
            DateTime.UtcNow.Add(_jwtSettings.ExpirationTime),
            signingCredentials: credentials);

        return (new JwtSecurityTokenHandler().WriteToken(token), token.Claims);
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
                ValidAudience = _jwtSettings.Audience,
                IssuerSigningKey = mySecurityKey
            }, out SecurityToken validatedToken);
        }
        catch
        {
            return false;
        }

        return true;
    }

    public IEnumerable<Claim> CopyClaims(JwtSecurityToken copy)
    {
        return new Claim[]
        {
            copy.Claims.Single(x => x.Type == ClaimTypes.NameIdentifier),
            copy.Claims.Single(x => x.Type == JwtRegisteredClaimNames.Email),
            copy.Claims.Single(x => x.Type == ClaimsIdentity.DefaultRoleClaimType),
            new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
    }

    public IEnumerable<Claim> GenerateClaims(string email, string? role)
    {
        return new Claim[]
        {
            new (ClaimTypes.NameIdentifier, email),
            new (JwtRegisteredClaimNames.Email, email),
            new (ClaimsIdentity.DefaultRoleClaimType, role ?? "None"),
            new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
    }
}
