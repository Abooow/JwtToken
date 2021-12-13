# ASP.NET Core 6 - JWT Authentication

This repo is just a basic demonstration on how [JWT](https://jwt.io/) token authentication can be used in a ASP.NET Core app.

The branches [master](https://github.com/Abooow/JwtToken/tree/master) and [basic](https://github.com/Abooow/JwtToken/tree/basic) shows how to create a JWT token without any encrytion, the contents of the token can still not be tampered with but the claims can easily be viewed.
If you don't want your users to be able to see the content of the token, then you could encrypt it, check out the [encrypted-token](https://github.com/Abooow/JwtToken/tree/encrypted-token) branch that achieves this.

---

The JWT [authentication handler](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/?view=aspnetcore-6.0) is added by the [.AddJwtBearer()](/src/Program.cs#L32) extension method which is provided by the [Microsoft.AspNetCore.Authentication.JwtBearer](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.JwtBearer) NuGet package, this is what manages what to do when a resource marked with the [Authorize] attribute is requested.

[Generating tokens](/src/TokenService.cs#L18) is handled by the [TokenService](/src/TokenService.cs) class but decoding and validation of tokens is handled by the JwtAuthenticationHandler, described in the previous section. The TokenService class does have a [DecodeToken()](/src/TokenService.cs#L33) method, but it's only used by the [TestToken](/src/TokenService.cs#L33) controller method.

(I know i have used the word "handle" quite a lot here, but i hope you can handle it.)

JWT settings can be found in [appsettings.json](/src/appsettings.json#L9)
