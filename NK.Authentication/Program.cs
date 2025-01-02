using Duende.IdentityServer.Models;
using Duende.IdentityServer;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using NK.Authentication.Data;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});
// IdentityServer�̐ݒ�
builder.Services.AddIdentityServer()
    .AddDeveloperSigningCredential() // �J���p�̏����L�[�𐶐�
    .AddInMemoryClients(new List<Client>
    {
        new Client
        {
            ClientId = "nk_app",
            AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
            ClientSecrets = { new Secret("secret".Sha256()) },
            AllowedScopes = { "openid", "profile", "api" }
        }
    })
    .AddInMemoryApiScopes(new List<ApiScope>
    {
        new ApiScope("api", "NK API")
    })
    .AddInMemoryIdentityResources(new List<IdentityResource>
    {
        new IdentityResources.OpenId(),
        new IdentityResources.Profile()
    })
    .AddTestUsers(new List<Duende.IdentityServer.Test.TestUser>
    {
        new Duende.IdentityServer.Test.TestUser
        {
            SubjectId = "1",
            Username = "test",
            Password = "password",
            Claims = new List<System.Security.Claims.Claim>
            {
                new System.Security.Claims.Claim("name", "Test User"),
                new System.Security.Claims.Claim("email", "test@example.com")
            }
        }
    });

builder.Services.AddAuthentication(options =>
{
    // �f�t�H���g�̔F�؃X�L�[���� "Bearer"�iJWT�j�ɐݒ�
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer("Bearer", options =>
{
    options.Authority = "https://localhost:7088"; // IdentityServer �� URL
    options.Audience = "api"; // �X�R�[�v��
    options.RequireHttpsMetadata = true; // HTTPS��K�{��
})
.AddGoogle("Google", options =>
{
    options.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
    options.CallbackPath = "/signin-google"; // Google�F�،�̃��_�C���N�g��
});


builder.Services.AddControllers();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();

// IdentityServer �~�h���E�F�A���g�p
app.UseIdentityServer();

// �F�؁E�F�~�h���E�F�A���g�p
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
