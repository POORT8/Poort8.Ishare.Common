using System.Text.Json.Serialization;

namespace Poort8.Ishare.Common.Capabilities;

public class CapabilitiesInfo
{
    public CapabilitiesInfo(string partyId, List<string> roles, string version)
    {
        PartyId = partyId;
        IshareRoles = roles.Select(r => new IshareRole(r)).ToList();
        SupportedVersions = new List<SupportedVersion> { new SupportedVersion(version) };
    }

    [JsonPropertyName("party_id")]
    public string PartyId { get; set; }

    [JsonPropertyName("ishare_roles")]
    public List<IshareRole> IshareRoles { get; set; }

    [JsonPropertyName("supported_versions")]
    public List<SupportedVersion> SupportedVersions { get; set; }
}

public class IshareRole
{
    public IshareRole(string role)
    {
        Role = role;
    }
    [JsonPropertyName("role")]
    public string Role { get; set; }
}

public class SupportedVersion
{
    public SupportedVersion(string version)
    {
        Version = version;
        SupportedFeatures = new List<object>();
    }
    [JsonPropertyName("version")]
    public string Version { get; set; }

    [JsonPropertyName("supported_features")]
    public List<object> SupportedFeatures { get; set; }
}

public class PublicEndpoints
{
    public PublicEndpoints(List<Endpoint> publicEndpoints)
    {
        Public = publicEndpoints;
    }
    [JsonPropertyName("public")]
    public List<Endpoint> Public { get; set; }
}

public class RestrictedEndpoints
{
    public RestrictedEndpoints(List<Endpoint> restrictedEndpoints)
    {
        Restricted = restrictedEndpoints;
    }
    [JsonPropertyName("restricted")]
    public List<Endpoint> Restricted { get; set; }
}

public class Endpoint
{
    public Endpoint(string id, string feature, string description, string url, string? tokenEndpoint = null)
    {
        Id = id;
        Feature = feature;
        Description = description;
        Url = url;
        TokenEndpoint = tokenEndpoint;
    }
    [JsonPropertyName("id")]
    public string Id { get; set; }

    [JsonPropertyName("feature")]
    public string Feature { get; set; }

    [JsonPropertyName("description")]
    public string Description { get; set; }

    [JsonPropertyName("url")]
    public string Url { get; set; }

    [JsonPropertyName("token_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenEndpoint { get; set; }
}