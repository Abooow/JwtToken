# ASP.NET Core 6 - JWT Authentication

This repository is just a basic demonstration on how encrypted [JWT](https://jwt.io/) token authentication can be used in a ASP.NET Core app.

This branch ([encrypted-token](https://github.com/Abooow/JwtToken/tree/encrypted-token)) demonstrates how to create and encrypt a JWT token.
If you don't need a encrypted token then check out either the [master](https://github.com/Abooow/JwtToken/tree/master) or [basic](https://github.com/Abooow/JwtToken/tree/basic) branches.

---

A [custom authentication handler (EncryptedJwtAuthenticationHandler)](/src/EncryptedJwtAuthenticationHandler.cs) is configured in [Program.cs](/src/Program.cs#L30) to handle what to do whenever a resource marked with the [Authorize] attribute is requested.

[Generating and encrypting tokens](/src/TokenService.cs#L23) is handled by the [TokenService](/src/TokenService.cs) class.
Decrypting, decoding and validation of tokens is handled by [EncryptedJwtAuthenticationHandler](/src/EncryptedJwtAuthenticationHandler.cs), witch uses the TokenService to call the [DecodeToken()](/src/TokenService.cs#L41) method.

The TokenService class uses the built in [DataProtectionProvider](https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/using-data-protection?view=aspnetcore-6.0) to encrypt and decrypt tokens.

JWT settings can be found in [appsettings.json](/src/appsettings.json#L9)
