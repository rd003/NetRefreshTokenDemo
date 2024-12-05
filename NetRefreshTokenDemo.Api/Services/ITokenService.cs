using System.Security.Claims;

namespace NetRefreshTokenDemo.Api.Services;

public interface ITokenService
{
    string GetAccessToken(IEnumerable<Claim> claim);
    string GenerateRefreshToken();
    ClaimsPrincipal GetPrincipalFromExpiredToken(string accessToken);
}
