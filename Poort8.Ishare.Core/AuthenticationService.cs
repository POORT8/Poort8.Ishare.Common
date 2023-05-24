using LazyCache;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Poort8.Ishare.Core.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Poort8.Ishare.Core;

public class AuthenticationService : IAuthenticationService
{
    private readonly ILogger<AuthenticationService> _logger;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;
    private readonly IAppCache? _memoryCache;
    private readonly ICertificateProvider _certificateProvider;
    private readonly string _clientId;

    public AuthenticationService(
        ILogger<AuthenticationService> logger,
        IConfiguration configuration,
        IHttpClientFactory httpClientFactory,
        IAppCache? memoryCache,
        ICertificateProvider certificateProvider)
    {
        _logger = logger;
        _configuration = configuration;
        _httpClient = httpClientFactory.CreateClient(nameof(AuthenticationService));
        _memoryCache = memoryCache;
        _certificateProvider = certificateProvider;
        _clientId = configuration["ClientId"]!;
    }

    public string CreateAccessToken(string audience)
    {
        return CreateToken(audience, 3600);
    }

    public string CreateTokenWithClaims(string? audience, IReadOnlyList<Claim> additionalClaims)
    {
        return CreateToken(audience, additionalClaims: additionalClaims);
    }

    public string CreateClientAssertion(string audience, int expSeconds = 30)
    {
        return CreateToken(audience, expSeconds);
    }

    private string CreateToken(string? audience, int expSeconds = 30, IReadOnlyList<Claim>? additionalClaims = null)
    {
        var claims = new ClaimsIdentity();
        claims.AddClaim(new Claim("sub", _clientId));
        claims.AddClaim(new Claim("jti", Guid.NewGuid().ToString()));

        if (additionalClaims is not null)
        {
            claims.AddClaims(additionalClaims);
        }

        var tokenHandler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };
        var token = tokenHandler.CreateJwtSecurityToken(
            issuer: _clientId,
            audience: audience,
            subject: claims,
            notBefore: DateTime.UtcNow,
            expires: DateTime.UtcNow.AddSeconds(expSeconds),
            issuedAt: DateTime.UtcNow,
            signingCredentials: _certificateProvider.GetSigningCredentials());

        token.Header.Remove("kid");
        token.Header.Remove("x5t");
        token.Header.Add("x5c", _certificateProvider.GetChainString());

        return tokenHandler.WriteToken(token);
    }

    public void ValidateAuthorizationHeader(string validIssuer, StringValues authorizationHeader)
    {
        if (authorizationHeader.Count != 1 || authorizationHeader[0]?.StartsWith("Bearer ") != true)
        {
            _logger.LogError("Invalid authorization header: {authorizationHeader}", authorizationHeader!);
            throw new Exception("Invalid authorization header.");
        }

        ValidateAccessToken(validIssuer, authorizationHeader[0]!.Replace("Bearer ", ""));
    }

    public void ValidateAccessToken(string validIssuer, string accessToken)
    {
        ValidateToken(validIssuer, accessToken, 3600, false, false);
    }

    public void ValidateToken(string validIssuer, string token, int expSeconds = 30, bool verifyChain = true, bool validateAudienceWithClientId = true)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };
            var jwtToken = handler.ReadJwtToken(token);
            var chain = JsonSerializer.Deserialize<string[]>(jwtToken.Header.X5c);
            if (chain is null) { throw new Exception("Empty x5c header."); }
            var signingCertificate = new X509Certificate2(Convert.FromBase64String(chain.First()));

            if (string.IsNullOrEmpty(jwtToken.Payload.Jti)) { throw new Exception("The 'jti' claim is missing from the client assertion."); }
            if (jwtToken.Payload.Exp != jwtToken.Payload.Iat + expSeconds) { throw new Exception("The 'exp' and 'iat' claims do not equal 'exp = iat + 30 or 3600'."); }
            if (jwtToken.Payload.Iss != jwtToken.Payload.Sub) { throw new Exception("The 'iss' claim is not equal to the 'sub' claim."); }

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAlgorithms = new List<string>() { "RS256" },
                ValidTypes = new List<string>() { "JWT" },
                ValidateIssuer = true,
                ValidIssuer = validIssuer,
                ValidateAudience = validateAudienceWithClientId,
                ValidAudience = _clientId,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new X509SecurityKey(signingCertificate),
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ClockSkew = TimeSpan.FromSeconds(30)
                //TODO: ValidateTokenReplay
            };

            if (verifyChain) { VerifyX5cChain(chain, signingCertificate); }

            handler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
        }
        catch (Exception e)
        {
            _logger.LogError("Token validation error, for client id {clientId} and assertion {assertion}. With message: {msg}", validIssuer, token, e.Message);
            throw;
        }
    }

    public async Task<string> GetAccessTokenAtPartyAsync(string partyId, string tokenUrl)
    {
        string accessToken;
        if (_memoryCache == null)
        {
            var tokenResponse = await GetAccessTokenAsync(partyId, tokenUrl);
            if (tokenResponse == null) { throw new Exception($"Did not receive an access token from {partyId}."); }
            accessToken = tokenResponse.AccessToken!;
        }
        else
        {
            accessToken = await _memoryCache.GetOrAddAsync($"AccessToken-{partyId}", async entry =>
            {
                var tokenResponse = await GetAccessTokenAsync(partyId, tokenUrl);
                if (tokenResponse == null) { throw new Exception($"Did not receive an access token from {partyId}."); }
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(tokenResponse.ExpiresIn - 60);
                return tokenResponse.AccessToken!;
            });
        }

        return accessToken;
    }

    private async Task<TokenResponse> GetAccessTokenAsync(string partyId, string tokenUrl)
    {
        try
        {
            var clientAssertion = CreateClientAssertion(partyId);
            var formData = new[]
            {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>("scope", "iSHARE"),
                    new KeyValuePair<string, string>("client_id", _configuration["ClientId"]!),
                    new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    new KeyValuePair<string, string>("client_assertion", clientAssertion)
            };

            var response = await _httpClient.PostAsync(tokenUrl, new FormUrlEncodedContent(formData));
            response.EnsureSuccessStatusCode();
            var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();

            _logger.LogInformation("Received token from party {party}", partyId);
            return tokenResponse ?? throw new Exception("TokenResponse is null.");
        }
        catch (Exception e)
        {
            _logger.LogError("Could not get access token from {partyId}: {msg}", partyId, e.Message);
            throw;
        }
    }

    private static void VerifyX5cChain(string[] chainString, X509Certificate2 signingCertificate)
    {
        var chainCertificates = new X509Certificate2Collection();
        foreach (var certificate in chainString.Skip(1))
        {
            chainCertificates.Add(new X509Certificate2(Convert.FromBase64String(certificate)));
        }
        var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(chainCertificates);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        var isVerified = chain.Build(signingCertificate);

        var keyUsages = signingCertificate.Extensions.OfType<X509KeyUsageExtension>();
        if (!keyUsages.Any(u => u.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature)))
        {
            throw new Exception("Signing certificate does not have a digital signature key usage.");
        };

        if (!isVerified) { throw new Exception("Certificate chain is not verified."); }
    }
}
