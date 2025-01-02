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
// IdentityServerの設定
builder.Services.AddIdentityServer()
    .AddDeveloperSigningCredential() // 開発用の署名キーを生成
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
    // デフォルトの認証スキームを "Bearer"（JWT）に設定
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer("Bearer", options =>
{
    options.Authority = "https://localhost:7088"; // IdentityServer の URL
    options.Audience = "api"; // スコープ名
    options.RequireHttpsMetadata = true; // HTTPSを必須化
})
.AddGoogle("Google", options =>
{
    options.ClientId = builder.Configuration["Authentication:Google:ClientId"]!;
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]!;
    options.CallbackPath = "/signin-google"; // Google認証後のリダイレクト先
});


builder.Services.AddControllers();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();

// IdentityServer ミドルウェアを使用
app.UseIdentityServer();

// 認証・認可ミドルウェアを使用
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
