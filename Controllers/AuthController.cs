using System.Security.Claims;
using JwtAuth.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

namespace JwtAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private static User _user = new User();

        [HttpPost("register")]
        public ActionResult<User> Register(UserDTO request)
        {
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            _user.Username = request.Username;
            _user.PasswordHash = passwordHash;

            return Ok(_user);
        }
        
        [HttpPost("login")]
        public ActionResult<User> Login(UserDTO request)
        {
            if (_user.Username != request.Username)
            {
                return BadRequest("User not found.");
            }

            if (!BCrypt.Net.BCrypt.Verify(request.Password, _user.PasswordHash))
            {
                return BadRequest("Wrong password.");
            }

            return Ok(_user);
        }

        // private string CreateToken(User user)
        // {
        //     List<Claim> claims = new List<Claim>
        //     {
        //         new Claim()
        //     }
        // }
    }
}