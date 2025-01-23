using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using webapp.Data;
using webapp.Models;

namespace webapp.Controllers;

public class AccountController : Controller
{
    private readonly IConfiguration _configuration;
    private readonly MyDbContext _context;
    

    public AccountController(MyDbContext context, IConfiguration configuration)
    {
        _context = context;
        _configuration = configuration;
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Register(User model)
    {
        if (ModelState.IsValid)
        {
            var user = new User
            {
                Username = model.Username,
                Email = model.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(model.Password)
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return RedirectToAction("Login");
        }

        return View(model);
    }
    
    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }
    
    [HttpPost]
    public Task<IActionResult> Login(User model)
    {
        if (ModelState.IsValid)
        {
            var user = _context.Users.SingleOrDefault(u => u.Username == model.Username);
        
            if (user != null && BCrypt.Net.BCrypt.Verify(model.Password, user.Password))
            {
                
                // Kullanıcı doğrulandı, session veya token eklenebilir
                var tokenString = generateToken(user);
                Response.Cookies.Append("token", tokenString);
                return Task.FromResult<IActionResult>(RedirectToAction("Home", "Home"));
            }

            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        }

        return Task.FromResult<IActionResult>(View(model));
    }
    
    [HttpPost]
    public Task<IActionResult> Logout()
    {
        // Çerezleri sil
        Response.Cookies.Delete("token");
        return Task.FromResult<IActionResult>(RedirectToAction("Index", "Home"));
    }

    

    private String generateToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email)
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}