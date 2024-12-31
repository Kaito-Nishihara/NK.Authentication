using Duende.IdentityServer.Models;
using Duende.IdentityServer;

var builder = WebApplication.CreateBuilder(args);

// IdentityServerの設定
builder.Services.AddIdentityServer()
    .AddDeveloperSigningCredential() // 開発用の署名キーを生成
    .AddInMemoryClients(new List<Client>
    {
        new Client
        {
            ClientId = "aeon_app",
            AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
            ClientSecrets = { new Secret("secret".Sha256()) },
            AllowedScopes = { "openid", "profile", "api" }
        }
    })
    .AddInMemoryApiScopes(new List<ApiScope>
    {
        new ApiScope("api", "AEON API")
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

builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.Authority = "https://localhost:7088"; // IdentityServer の URL
        options.Audience = "api"; // スコープ名
        options.RequireHttpsMetadata = true; // HTTPSを必須化
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
