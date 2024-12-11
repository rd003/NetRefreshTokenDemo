using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace NetRefreshTokenDemo.Api.Services;

public class TokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    /// <summary>
    /// Generates a JWT access token with the specified claims.
    /// </summary>
    /// <param name="claims">A collection of claims to be included in the token.</param>
    /// <returns>A signed JWT access token as a string.</returns>
    public string GenerateAccessToken(IEnumerable<Claim> claims)
    {
        var tokenHandler = new JwtSecurityTokenHandler();

        // Create a symmetric security key using the secret key from the configuration.
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = _configuration["JWT:ValidIssuer"],
            Audience = _configuration["JWT:ValidAudience"],
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.Now.AddMinutes(15),
            SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }


    /// <summary>
    /// Generates a refresh token.
    /// </summary>
    /// <returns>A base64 encoded string representing the refresh token.</returns>
    public string GenerateRefreshToken()
    {
        // Create a 32-byte array to hold cryptographically secure random bytes
        var randomNumber = new byte[32];

        // Use a cryptographically secure random number generator 
        // to fill the byte array with random values
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(randomNumber);

        // Convert the random bytes to a base64 encoded string 
        return Convert.ToBase64String(randomNumber);
    }

    /// <summary>
    /// Extracts the claims principal from an expired JWT access token.
    /// </summary>
    /// <param name="accessToken">The expired JWT access token.</param>
    /// <returns>The claims principal containing the claims from the expired token.</returns>
    /// <exception cref="SecurityTokenException">Thrown if the token is invalid or its signing algorithm is not HmacSha256.</exception>

    public ClaimsPrincipal GetPrincipalFromExpiredToken(string accessToken)
    {
        // Define the token validation parameters used to validate the token.
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = _configuration["JWT:ValidAudience"],
            ValidIssuer = _configuration["JWT:ValidIssuer"],
            ValidateLifetime = false, // don't forget to add this line.
            ClockSkew = TimeSpan.Zero,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:secret"]))
        };

        var tokenHandler = new JwtSecurityTokenHandler();

        // Validate the token and extract the claims principal and the security token.
        var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);

        // Cast the security token to a JwtSecurityToken for further validation.
        var jwtSecurityToken = securityToken as JwtSecurityToken;

        // Ensure the token is a valid JWT and uses the HmacSha256 signing algorithm.
        // If no throw new SecurityTokenException
        if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        // return the principal
        return principal;
    }
}

