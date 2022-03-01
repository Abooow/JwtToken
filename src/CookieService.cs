namespace JwtToken;

public class CookieService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public CookieService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public bool ContainsSingleCookie(string key)
    {
        return _httpContextAccessor.HttpContext!.Request.Cookies.Count(cookie => cookie.Key == key) == 1;
    }

    public string? GetCookie(string key)
    {
        return _httpContextAccessor.HttpContext!.Request.Cookies[key];
    }

    public void SetCookie(string key, string value, DateTime? expireTime)
    {
        var cookieOptions = new CookieOptions
        {
            Expires = expireTime,
            Secure = true,
            HttpOnly = true,
            SameSite = SameSiteMode.Strict
        };

        _httpContextAccessor.HttpContext!.Response.Cookies.Append(key, value, cookieOptions);
    }

    public void SetCookie(string key, string value, DateTime? expireTime, bool isSecure, bool isHttpOnly, SameSiteMode sameSiteMode)
    {
        var cookieOptions = new CookieOptions
        {
            Expires = expireTime,
            Secure = isSecure,
            HttpOnly = isHttpOnly,
            SameSite = sameSiteMode
        };

        _httpContextAccessor.HttpContext!.Response.Cookies.Append(key, value, cookieOptions);
    }

    public void DeleteCookie(string key)
    {
        _httpContextAccessor.HttpContext!.Response.Cookies.Delete(key);
    }
}
