using LazyCache;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Poort8.Ishare.Core.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core;

public class SchemeOwnerService : ISchemeOwnerService
{
    private readonly ILogger<SchemeOwnerService> _logger;
    private readonly IConfiguration _configuration;
    private readonly IAppCache? _memoryCache;
    private readonly HttpClient _httpClient;
    private readonly IAuthenticationService _authenticationService;
    private readonly Dictionary<string, Uri> registrarUris = new()
    {
        { "EORI-BRANCH", new Uri("https://ds-admin.jomco.nl") },
        { "EORI-BRANCH-O", new Uri("https://ds-admin-o.jomco.nl") }
    };

    public SchemeOwnerService(
        ILogger<SchemeOwnerService> logger,
        IConfiguration configuration,
        IAppCache? memoryCache,
        IHttpClientFactory httpClientFactory,
        IAuthenticationService authenticationService)
    {
        _logger = logger;
        _configuration = configuration;
        //_memoryCache = memoryCache;

        _httpClient = httpClientFactory.CreateClient(nameof(SchemeOwnerService));

        _authenticationService = authenticationService;
    }

    private async Task<List<TrustedCertificateAuthority>> GetTrustedListAsync(string? registrar)
    {
        List<TrustedCertificateAuthority> trustedList;
        if (_memoryCache == null)
        {
            trustedList = await GetTrustedListAtSchemeOwnerAsync(registrar);
        }
        else
        {
            trustedList = await _memoryCache.GetOrAddAsync("TrustedList", async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1);
                return await GetTrustedListAtSchemeOwnerAsync(registrar);
            });
        }

        return trustedList;
    }

    private async Task<List<TrustedCertificateAuthority>> GetTrustedListAtSchemeOwnerAsync(string? registrar)
    {
        try
        {
            var (uri, identifier) = GetUriAndIdentifier(registrar, "/trusted_list");

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await GetToken(registrar));
            var response = await _httpClient.GetFromJsonAsync<TrustedListResponse>(uri);

            if (response is null || response.TrustedListToken is null) { throw new Exception("TrustedList response is null."); }

            _authenticationService.ValidateToken(identifier, response.TrustedListToken);

            var handler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };
            var trustedListToken = handler.ReadJwtToken(response.TrustedListToken);
            var trustedListClaims = trustedListToken.Claims.Where(c => c.Type == "trusted_list").ToArray();

            var trustedList = new List<TrustedCertificateAuthority>();
            foreach (var claim in trustedListClaims)
            {
                var trustedListClaim = JsonSerializer.Deserialize<TrustedCertificateAuthority>(claim.Value);
                if (trustedListClaim is not null) { trustedList.Add(trustedListClaim); }
            }

            _logger.LogInformation("Received trusted list from scheme owener.");
            return trustedList;
        }
        catch (Exception e)
        {
            _logger.LogError("Could not get trusted list from scheme owner: {msg}", e.Message);
            throw;
        }
    }

    private (Uri, string) GetUriAndIdentifier(string? registrar, string relativeUri)
    {
        Uri uri;
        string identifier;
        if (string.IsNullOrEmpty(registrar))
        {
            uri = new Uri(new Uri(_configuration["SchemeOwnerUrl"]!), relativeUri);
            identifier = _configuration["SchemeOwnerIdentifier"]!;
        }
        else
        {
            var registrarIds = registrar.Split(',');
            uri = new Uri(registrarUris[registrarIds[0]], relativeUri);
            identifier = registrarIds[0];
        }

        _logger.LogInformation("Using registrar {identifier} on url {url}", identifier, uri.AbsoluteUri);

        return (uri, identifier);
    }

    private async Task<string> GetToken(string? registrar)
    {
        var (uri, identifier) = GetUriAndIdentifier(registrar, "/connect/token");
        return await _authenticationService.GetAccessTokenAtPartyAsync(identifier, uri.AbsoluteUri);
    }

    private async Task<PartyInfo> GetPartyAsync(string? registrar, string partyId, string certificateSubject)
    {
        PartyInfo partyInfo;
        if (_memoryCache == null)
        {
            partyInfo = await GetPartyAtSchemeOwnerAsync(registrar, partyId, certificateSubject);
        }
        else
        {
            partyInfo = await _memoryCache.GetOrAddAsync($"Party-{partyId}-{certificateSubject}", async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1);
                return await GetPartyAtSchemeOwnerAsync(registrar, partyId, certificateSubject);
            });
        }

        return partyInfo;
    }

    private async Task<PartyInfo> GetPartyAtSchemeOwnerAsync(string? registrar, string partyId, string certificateSubject)
    {
        try
        {
            var relativeUri = $"/parties?eori={partyId}&certificate_subject_name={certificateSubject}";
            var (uri, identifier) = GetUriAndIdentifier(registrar, relativeUri);

            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await GetToken(registrar));
            var response = await _httpClient.GetFromJsonAsync<PartiesResponse>(uri);

            if (response is null || response.PartiesToken is null) { throw new Exception("Parties response is null."); }

            _authenticationService.ValidateToken(identifier, response.PartiesToken);

            var handler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };
            var partiesToken = handler.ReadJwtToken(response.PartiesToken);
            var partiesTokenClaim = partiesToken.Claims.Where(c => c.Type == "parties_info").First();
            var partiesInfoClaim = JsonSerializer.Deserialize<PartiesClaim>(partiesTokenClaim.Value);

            if (partiesInfoClaim is null || partiesInfoClaim.Count > 1 || partiesInfoClaim.PartiesInfo is null) { throw new Exception("Received invalid parties info."); }

            _logger.LogInformation("Received party info for party {party}", partyId);
            return partiesInfoClaim.PartiesInfo.First() ?? throw new Exception("Received empty party info list.");
        }
        catch (Exception e)
        {
            _logger.LogError("Could not get party info from scheme owner: {msg}", e.Message);
            throw;
        }
    }

    public async Task VerifyCertificateIsTrustedAsync(string? registrar, string clientAssertion)
    {
        var handler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };
        var token = handler.ReadJwtToken(clientAssertion);
        var chain = JsonSerializer.Deserialize<string[]>(token.Header.X5c);
        if (chain is null) { throw new Exception("Empty x5c header."); }

        var trustedList = await GetTrustedListAsync(registrar);

        foreach (var chainCertificate in chain.Skip(1))
        {
            var certificate = new X509Certificate2(Convert.FromBase64String(chainCertificate));

            var sha256Thumbprint = GetSha256Thumbprint(certificate);

            //NOTE: Find match on SHA1 or SHA256 certificate thumbprint
            var trustedRoot = trustedList.Where(c =>
                c.CertificateFingerprint == certificate.Thumbprint || c.CertificateFingerprint == sha256Thumbprint).FirstOrDefault();

            if (trustedRoot is null ||
                trustedRoot.Status is null ||
                !trustedRoot.Status.Equals("granted", StringComparison.OrdinalIgnoreCase) ||
                trustedRoot.Validity is null ||
                !trustedRoot.Validity.Equals("valid", StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogError("Root certificate not in trusted list, or validity/status is invalid. Root certificate: {rootCertificate}", chain.Last());
                throw new Exception("Root certificate not trusted.");
            }
        }
    }

    public async Task VerifyPartyAsync(string? registrar, string partyId, string clientAssertion)
    {
        var handler = new JwtSecurityTokenHandler { MaximumTokenSizeInBytes = 1024 * 1024 * 2 };
        var token = handler.ReadJwtToken(clientAssertion);
        var chain = JsonSerializer.Deserialize<string[]>(token.Header.X5c);
        if (chain is null) { throw new Exception("Empty x5c header."); }
        var signingCertificate = new X509Certificate2(Convert.FromBase64String(chain.First()));

        var partyInfo = await GetPartyAsync(registrar, partyId, signingCertificate.Subject);

        if (partyInfo is null ||
            partyInfo.Adherence?.Status is null ||
            !partyInfo.Adherence.Status.Equals("active", StringComparison.OrdinalIgnoreCase) ||
            partyInfo.Adherence.StartDate > DateTime.Now ||
            partyInfo.Adherence.EndDate <= DateTime.Now)
        {
            _logger.LogError("Party info checks failed for party {partyId} and certificate subject {certificateSubject}", partyId, signingCertificate.Subject);
            throw new Exception("Party info checks failed.");
        }
    }

    private static string GetSha256Thumbprint(X509Certificate2 certificate)
    {
        var hasher = SHA256.Create();
        return Convert.ToHexString(hasher.ComputeHash(certificate.GetRawCertData()));
    }

    private class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
    }

    private class TrustedListResponse
    {
        [JsonPropertyName("trusted_list_token")]
        public string? TrustedListToken { get; set; }
    }

    private class PartiesResponse
    {
        [JsonPropertyName("parties_token")]
        public string? PartiesToken { get; set; }
    }

    private class PartiesClaim
    {
        [JsonPropertyName("count")]
        public int Count { get; set; }

        [JsonPropertyName("data")]
        public List<PartyInfo>? PartiesInfo { get; set; }
    }
}