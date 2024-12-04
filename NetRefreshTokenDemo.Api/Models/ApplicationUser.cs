using System;
using Microsoft.AspNetCore.Identity;

namespace NetRefreshTokenDemo.Api.Models;

public class ApplicationUser : IdentityUser
{
    public string Name { get; set; } = string.Empty;
}
