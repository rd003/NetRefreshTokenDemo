using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using NetRefreshTokenDemo.Api.Constants;
using NetRefreshTokenDemo.Api.Models;

namespace NetRefreshTokenDemo.Api.Data;

/// <summary>
/// Provides database seeding functionality for initial application setup
/// Handles database migrations, default user, and role creation
/// </summary>
public class DbSeeder
{
    /// <summary>
    /// Seeds initial application data, including database migrations and default admin user
    /// </summary>
    /// <param name="app">The application builder used to create a service scope</param>
    /// <returns>A task representing the asynchronous seeding operation</returns>
    public static async Task SeedData(IApplicationBuilder app)
    {
        // Create a scoped service provider to resolve dependencies
        using var scope = app.ApplicationServices.CreateScope();

        // resolve the logger server
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<DbSeeder>>();

        try
        {
            // Resolve AppDbContext service
            var context = scope.ServiceProvider.GetService<AppDbContext>();

            // Perform database migration if pending migrations exist
            // This ensures the database schema is up to date
            if (context.Database.GetPendingMigrations().Count() > 0)
            {
                await context.Database.MigrateAsync();
            }

            // Resolve other required services
            var userManager = scope.ServiceProvider.GetService<UserManager<ApplicationUser>>();
            var roleManager = scope.ServiceProvider.GetService<RoleManager<IdentityRole>>();

            // Check if any users exist to prevent duplicate seeding
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

                // Create Admin role if it doesn't exist
                if ((await roleManager.RoleExistsAsync(Roles.Admin)) == false)
                {
                    logger.LogInformation("Admin role is creating");
                    var roleResult = await roleManager.CreateAsync(new IdentityRole(Roles.Admin));

                    if (roleResult.Succeeded == false)
                    {
                        var roleErros = roleResult.Errors.Select(e => e.Description);
                        logger.LogError($"Failed to create admin role. Errors : {string.Join(",", roleErros)}");

                        return;
                    }
                    logger.LogInformation("Admin role is created");
                }

                // Attempt to create admin user
                var createUserResult = await userManager.CreateAsync(user: user, password: "Admin@123");

                // Validate user creation
                if (createUserResult.Succeeded == false)
                {
                    var errors = createUserResult.Errors.Select(e => e.Description);
                    logger.LogError(
                        $"Failed to create admin user. Errors: {string.Join(", ", errors)}"
                    );
                    return;
                }

                // adding role to user
                var addUserToRoleResult = await userManager.AddToRoleAsync(user: user, role: Roles.Admin);

                if (addUserToRoleResult.Succeeded == false)
                {
                    var errors = addUserToRoleResult.Errors.Select(e => e.Description);
                    logger.LogError($"Failed to add admin role to user. Errors : {string.Join(",", errors)}");
                }
                logger.LogInformation("Admin user is created");
            }
        }
        catch (Exception ex)
        {
            logger.LogCritical(ex.Message);
        }

    }
}
