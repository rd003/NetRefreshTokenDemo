using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NetRefreshTokenDemo.Api.Constants;
using NetRefreshTokenDemo.Api.Models;

namespace NetRefreshTokenDemo.Api.Data;

public static class DbSeeder
{
    public static async Task SeedData(IApplicationBuilder app)
    {
        try
        {
            using var scope = app.ApplicationServices.CreateScope();
            var context = scope.ServiceProvider.GetService<AppDbContext>();
            if (context.Database.GetPendingMigrations().Count() > 0)
            {
                await context.Database.MigrateAsync();
            }

            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider.GetService<RoleManager<IdentityRole>>();

            if (userManager.Users.Any() == false)
            {
                var user = new ApplicationUser
                {
                    Name = "Admin",
                    UserName = "admin@gmail.com",
                    Email = "admin@gmail.com",
                    EmailConfirmed = true,
                    SecurityStamp = Guid.NewGuid().ToString()
                };

                var createUserResult = await userManager.CreateAsync(user: user, password: "Admin@123");

                if (createUserResult.Succeeded == false) { return; }

                if ((await roleManager.RoleExistsAsync(Roles.Admin)) == false)
                {
                    await roleManager.CreateAsync(new IdentityRole(Roles.Admin));
                }

                await userManager.AddToRoleAsync(user: user, role: Roles.Admin);
            }
        }
        catch (Exception ex)
        {

        }

    }
}
