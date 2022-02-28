namespace JwtToken;

public class JwtSettings
{
    public string Key { get; set; }
    public string Issuer { get; set; }
    public TimeSpan ExpirationTime { get; set; }
}
