using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Moq;
using NK.Authentication.Controllers;
using NK.Authentication.Data;
using NK.Authentication.Models;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Test.NK.Authentication
{
    public class AuthControllerTests
    {
        private readonly AppDbContext _mockDbContext;
        private readonly Mock<IConfiguration> _mockConfiguration;
        private readonly AuthController _controller;

        public AuthControllerTests()
        {
            // Mock DbContext
            var options = new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase("TestDb").Options;
            _mockDbContext = new AppDbContext(options);

            // Mock Configuration
            _mockConfiguration = new Mock<IConfiguration>();
            _mockConfiguration.Setup(c => c["Jwt:Key"]).Returns(GenerateSecureKey());
            _mockConfiguration.Setup(c => c["Jwt:Issuer"]).Returns("https://localhost:5001");
            _mockConfiguration.Setup(c => c["Jwt:Audience"]).Returns("https://localhost:5001");
            _mockConfiguration.Setup(c => c["Smtp:Host"]).Returns("localhost");
            _mockConfiguration.Setup(c => c["Smtp:Port"]).Returns("1025");
            _mockConfiguration.Setup(c => c["Smtp:Username"]).Returns("testuser");
            _mockConfiguration.Setup(c => c["Smtp:Password"]).Returns("password123");
            _mockConfiguration.Setup(c => c["Smtp:FromEmail"]).Returns("no-reply@example.com");

            // Setup controller
            _controller = new AuthController(_mockDbContext, _mockConfiguration.Object);
            var httpContext = new DefaultHttpContext();
            _controller.ControllerContext = new ControllerContext
            {
                HttpContext = httpContext
            };
            var mockUrlHelper = new Mock<IUrlHelper>();
            mockUrlHelper
                .Setup(u => u.Action(It.IsAny<UrlActionContext>()))
                .Returns("http://localhost/Auth/ConfirmRegistration?token=testtoken");

            _controller.Url = mockUrlHelper.Object;
        }

        [Fact]
        public async Task Register_ShouldReturnOk_WhenEmailIsUnique()
        {
            // Arrange
            var request = new RegisterRequest
            {
                Email = "test+5@example.com",
                Password = "password123"
            };

            // Act
            var result = await _controller.Register(request);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal("Confirmation email sent. Please check your inbox.", okResult.Value);
        }

        [Fact]
        public async Task Register_ShouldReturnBadRequest_WhenEmailIsAlreadyInUse()
        {
            // Arrange
            var existingUser = new User
            {
                Email = "test@example.com",
                PasswordHash = "hashedpassword",
                Role = "User"
            };

            _mockDbContext.Users.Add(existingUser);
            await _mockDbContext.SaveChangesAsync();

            var request = new RegisterRequest
            {
                Email = "test@example.com",
                Password = "password123"
            };

            // Act
            var result = await _controller.Register(request);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal("Email is already in use.", badRequestResult.Value);
        }

        [Fact]
        public async Task Login_ShouldReturnOk_WithValidCredentials()
        {
            // Arrange
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword("password123");
            var user = new User
            {
                Email = "test+2@example.com",
                PasswordHash = hashedPassword,
                Role = "User"
            };

            _mockDbContext.Users.Add(user);
            await _mockDbContext.SaveChangesAsync();

            var request = new LoginRequest
            {
                Email = "test+2@example.com",
                Password = "password123"
            };

            // Act
            var result = await _controller.Login(request);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.NotNull(okResult.Value);
        }

        [Fact]
        public async Task Login_ShouldReturnUnauthorized_WithInvalidCredentials()
        {
            // Arrange
            var hashedPassword = BCrypt.Net.BCrypt.HashPassword("password123");
            var user = new User
            {
                Email = "test+3@example.com",
                PasswordHash = hashedPassword,
                Role = "User"
            };

            _mockDbContext.Users.Add(user);
            await _mockDbContext.SaveChangesAsync();

            var request = new LoginRequest
            {
                Email = "test+3@example.com",
                Password = "wrongpassword"
            };

            // Act
            var result = await _controller.Login(request);

            // Assert
            Assert.IsType<UnauthorizedObjectResult>(result);
        }

        [Fact]
        public async Task ConfirmRegistration_ShouldReturnOk_WithValidToken()
        {
            // Arrange
            var email = "test+4@example.com";
            var token = _controller.GenerateEmailToken(email);

            // Act
            var result = await _controller.ConfirmRegistration(token);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal("Account confirmed and created successfully.", okResult.Value);
        }

        [Fact]
        public async Task ConfirmRegistration_ShouldReturnBadRequest_WithInvalidToken()
        {
            // Arrange
            var token = "invalidtoken";

            // Act
            var result = await _controller.ConfirmRegistration(token);

            // Assert
            Assert.IsType<BadRequestObjectResult>(result);
        }

        [Fact]
        public async Task CheckRole_ShouldReturnOk_WhenUserIsAuthorizedAndFound()
        {
            // Arrange
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;

            using var context = new AppDbContext(options);

            // ユーザーをデータベースに追加
            var testUser = new User
            {
                Email = "test+6@example.com",
                Role = "Admin"
            };
            context.Users.Add(testUser);
            await context.SaveChangesAsync();

            // モックされた HttpContext の作成
            var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Email, "test+6@example.com")
    };
            var identity = new ClaimsIdentity(claims, "TestAuth");
            var claimsPrincipal = new ClaimsPrincipal(identity);

            var controller = new AuthController(context, Mock.Of<IConfiguration>());
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = claimsPrincipal
                }
            };

            // Act
            var result = await controller.CheckRole();

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            var response = okResult.Value as User;
            Assert.Equal("test+6@example.com", response!.Email);
            Assert.Equal("Admin", response!.Role);
        }

        [Fact]
        public async Task CheckRole_ShouldReturnUnauthorized_WhenEmailIsMissingInToken()
        {
            // Arrange
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;

            using var context = new AppDbContext(options);

            var controller = new AuthController(context, Mock.Of<IConfiguration>());
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(new ClaimsIdentity()) // クレームが空
                }
            };

            // Act
            var result = await controller.CheckRole();

            // Assert
            var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
            Assert.Equal("User is not authorized", unauthorizedResult.Value);
        }

        [Fact]
        public async Task CheckRole_ShouldReturnUnauthorized_WhenUserNotFound()
        {
            // Arrange
            var options = new DbContextOptionsBuilder<AppDbContext>()
                .UseInMemoryDatabase(Guid.NewGuid().ToString())
                .Options;

            using var context = new AppDbContext(options);

            // モックされた HttpContext の作成
            var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Email, "nonexistent@example.com")
    };
            var identity = new ClaimsIdentity(claims, "TestAuth");
            var claimsPrincipal = new ClaimsPrincipal(identity);

            var controller = new AuthController(context, Mock.Of<IConfiguration>());
            controller.ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = claimsPrincipal
                }
            };

            // Act
            var result = await controller.CheckRole();

            // Assert
            var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
            Assert.Equal("User not found", unauthorizedResult.Value);
        }


        public static string GenerateSecureKey()
        {
            using (var hmac = new HMACSHA256())
            {
                return Convert.ToBase64String(hmac.Key);
            }
        }
    }
}