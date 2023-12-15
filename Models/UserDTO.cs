namespace JwtAuth.Models;

public class UserDTO
{
    public required string Username { get; set; } = string.Empty;
    public required string Password { get; set; } = string.Empty;
}