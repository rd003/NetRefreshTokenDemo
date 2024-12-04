using System.ComponentModel.DataAnnotations;

namespace NetRefreshTokenDemo.Api.Models;

public class TokenInfo
{
    public int Id { get; set; }

    [Required]
    [MaxLength(30)]
    public string Username { get; set; } = string.Empty;

    [Required]
    [MaxLength(30)]
    public string RefreshToken { get; set; } = string.Empty;

    [Required]
    public DateTime ExpiredAt { get; set; }
}