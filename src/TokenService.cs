using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

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

    public string GenerateToken(IEnumerable<Claim> claims)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var securityToken = new JwtSecurityToken(
            _jwtSettings.Issuer,
            _jwtSettings.Issuer,
            claims,
            expires: DateTime.UtcNow.Add(_jwtSettings.ExpirationTime),
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
