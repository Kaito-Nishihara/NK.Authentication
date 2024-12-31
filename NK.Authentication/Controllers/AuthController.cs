using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using NK.Authentication.Data;
using NK.Authentication.Models;
using Org.BouncyCastle.Crypto.Generators;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;

#nullable disable
namespace NK.Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(AppDbContext context, IConfiguration configuration) : ControllerBase
    {       

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if (user != null && VerifyPassword(request.Password, user.PasswordHash))
            {
                var token = GenerateJwtToken(user.Email);
                return Ok(new { Token = token });
            }

            return Unauthorized("Invalid credentials");
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            // メールアドレスの重複チェック
            if (await context.Users.AnyAsync(u => u.Email == request.Email))
            {
                return BadRequest("Email is already in use.");
            }

            // トークン生成
            var token = GenerateEmailToken(request.Email);

            // メール送信
            var verificationUrl = Url.Action("ConfirmRegistration", "Auth", new { token = token }, Request.Scheme);
            await SendEmailAsync(request.Email, "Account Confirmation", $"Please confirm your account by clicking <a href='{verificationUrl}'>here</a>.");

            return Ok("Confirmation email sent. Please check your inbox.");
        }

        [HttpGet("confirm-registration")]
        public async Task<IActionResult> ConfirmRegistration(string token)
        {
            // トークンを検証
            var email = ValidateEmailToken(token);
            if (email == null)
            {
                return BadRequest("Invalid or expired token.");
            }

            // メールアドレスの重複チェック
            if (await context.Users.AnyAsync(u => u.Email == email))
            {
                return BadRequest("Email is already in use.");
            }

            // デフォルトのパスワードを設定してアカウントを作成
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword("DefaultPassword123");

            var newUser = new User
            {
                Email = email,
                PasswordHash = hashedPassword,
                Role = "User"
            };

            context.Users.Add(newUser);
            await context.SaveChangesAsync();

            return Ok("Account confirmed and created successfully.");
        }

        [HttpGet("check-role")]
        [Authorize] // JWT トークンが必要
        public async Task<IActionResult> CheckRole()
        {
            // トークンからユーザーの Email を取得
            var email = User.FindFirst(ClaimTypes.Email)?.Value;

            if (string.IsNullOrEmpty(email))
            {
                return Unauthorized("User is not authorized");
            }

            // データベースからユーザー情報を取得
            var user = await context.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                return Unauthorized("User not found");
            }

            // ユーザーの権限を確認（例: 管理者権限をチェック）
            bool isAdmin = user.Role == "Admin"; // Role プロパティが必要

            return Ok(user);
        }

        private bool VerifyPassword(string password, string passwordHash)
        {
            // BCryptを使用してハッシュを検証
            return BCrypt.Net.BCrypt.Verify(password, passwordHash);
        }

        private string GenerateJwtToken(string email)
        {
            // トークンの署名キー
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // トークンに含めるクレーム（ユーザー情報など）
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, email),
                new Claim(ClaimTypes.Email, email),
                new Claim(ClaimTypes.Role, "User")
            };

            // トークンの作成
            var token = new JwtSecurityToken(
                issuer: configuration["Jwt:Issuer"],
                audience: configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1), // 有効期限1時間
                signingCredentials: creds);

            // トークンを文字列にして返す
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public string GenerateEmailToken(string email)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Email, email)
            };

            var token = new JwtSecurityToken(
                issuer: configuration["Jwt:Issuer"],
                audience: configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(24), // 24時間有効
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string ValidateEmailToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var principal = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = configuration["Jwt:Issuer"],
                    ValidAudience = configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"])),
                    ValidateLifetime = true
                }, out SecurityToken validatedToken);

                return principal.FindFirstValue(ClaimTypes.Email);
            }
            catch
            {
                return null;
            }
        }

        private async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            using (var smtpClient = new SmtpClient(configuration["Smtp:Host"], int.Parse(configuration["Smtp:Port"])))
            {
                smtpClient.Credentials = new System.Net.NetworkCredential(
                    configuration["Smtp:Username"],
                    configuration["Smtp:Password"]);
                smtpClient.EnableSsl = false; // MailHogではSSLは不要

                var mailMessage = new MailMessage
                {
                    From = new MailAddress(configuration["Smtp:FromEmail"]),
                    Subject = subject,
                    Body = body,
                    IsBodyHtml = true
                };

                mailMessage.To.Add(toEmail);

                // 非同期でメールを送信
                await smtpClient.SendMailAsync(mailMessage);
            }
        }

    }
}
