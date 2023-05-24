using Microsoft.Extensions.Primitives;
using System.Security.Claims;

namespace Poort8.Ishare.Core;

public interface IAuthenticationService
{
    string CreateAccessToken(string audience);
    string CreateTokenWithClaims(string? audience, IReadOnlyList<Claim> additionalClaims);
    string CreateClientAssertion(string audience, int expSeconds = 30);
    void ValidateAuthorizationHeader(string validIssuer, StringValues authorizationHeader);
    void ValidateAccessToken(string validIssuer, string accessToken);
    void ValidateToken(string validIssuer, string token, int expSeconds = 30, bool verifyChain = true, bool validateAudienceWithClientId = true);
    Task<string> GetAccessTokenAtPartyAsync(string partyId, string tokenUrl);
}