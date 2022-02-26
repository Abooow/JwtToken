using JwtToken;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(x =>
{
    x.AddSecurityDefinition("EncryptedBearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme()
    {
        Description = "Jwt Token Description",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
    });
});

var jwtSettingsSection = builder.Configuration.GetSection(nameof(JwtSettings));
var jwtSettings = jwtSettingsSection.Get<JwtSettings>();
builder.Services.Configure<JwtSettings>(jwtSettingsSection);

builder.Services.AddTransient<TokenService>();

builder.Services.AddAuthentication(x =>
{
    x.DefaultChallengeScheme = Constants.AuthenticationScheme;
    x.DefaultAuthenticateScheme = Constants.AuthenticationScheme;
    x.DefaultScheme = Constants.AuthenticationScheme;
})
    .AddScheme<EncryptedJwtAuthenticationSchemeOptions, EncryptedJwtAuthenticationHandler>(Constants.AuthenticationScheme, null);

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
