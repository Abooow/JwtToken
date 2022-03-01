using JwtToken;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(x =>
{
    x.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme()
    {
        Description = "Jwt Token Description",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
    });
});

var jwtSettingsSection = builder.Configuration.GetSection(nameof(JwtSettings));
var jwtSettings = jwtSettingsSection.Get<JwtSettings>();
builder.Services.Configure<JwtSettings>(jwtSettingsSection);

builder.Services.AddHttpContextAccessor();
builder.Services.AddTransient<CookieService>();
builder.Services.AddTransient<TokenService>();
builder.Services.AddTransient<RefreshTokenRepository>();

builder.Services.AddAuthentication(x =>
{
    x.DefaultChallengeScheme = Constants.AuthenticationScheme;
    x.DefaultAuthenticateScheme = Constants.AuthenticationScheme;
    x.DefaultScheme = Constants.AuthenticationScheme;
})
    .AddScheme<AuthenticationSchemeOptions, AuthenticationHandler>(Constants.AuthenticationScheme, null);

// Configure the HTTP request pipeline.
var app = builder.Build();
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
