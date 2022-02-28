using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JwtToken;

public class TokenService
{
    private readonly IDataProtectionProvider _dataProtectionProvider;
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<TokenService> _logger;

    public TokenService(IDataProtectionProvider dataProtectionProvider, IOptions<JwtSettings> jwtSettings, ILogger<TokenService> logger)
    {
        _dataProtectionProvider = dataProtectionProvider;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
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

    private string GenerateToken(IEnumerable<Claim> claims, DateTime expires)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var securityToken = new JwtSecurityToken(
            _jwtSettings.Issuer,
            _jwtSettings.Audience,
            claims,
            notBefore: null,
            expires,
            signingCredentials: credentials);

        string token = new JwtSecurityTokenHandler().WriteToken(securityToken);
        var protector = _dataProtectionProvider.CreateProtector(_jwtSettings.EncryptiondKey);

        return protector.Protect(token);
    }

    public JwtSecurityToken? DecodeToken(string encryptedToken)
    {
        string token;
        try
        {
            var protector = _dataProtectionProvider.CreateProtector(_jwtSettings.EncryptiondKey);
            token = protector.Unprotect(encryptedToken);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Failed to decrypt token.");
            return null;
        }

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
