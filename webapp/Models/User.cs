namespace webapp.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string Password { get; set; } // Parola hash'lenmiş olacak
    public string? Email { get; set; }
}