using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtAuth.API.Models;
using JwtAuth.Application.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuth.Application.Services;

public class AuthService : IAuthService
{

    private static User _user = new User();
    
    public User Register(UserDTO request)
    {
        string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

        _user.Username = request.Username;
        _user.PasswordHash = passwordHash;

        return _user;
    }

    public string Login(UserDTO request)
    {
        if (_user.Username != request.Username)
        {
            throw new Exception("User not found.");
        }

        if (!BCrypt.Net.BCrypt.Verify(request.Password, _user.PasswordHash))
        {
            throw new Exception("Wrong Password");
        }

        string token = CreateToken(_user);
        return token;
    }
    
    private string CreateToken(User user)
    {
        var key = Encoding.ASCII.GetBytes(Settings.Secret);
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha512Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}