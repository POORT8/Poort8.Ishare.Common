using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core.Models;

public class TrustedCertificateAuthority
{
    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    [JsonPropertyName("certificate_fingerprint")]
    public string? CertificateFingerprint { get; set; }

    [JsonPropertyName("validity")]
    public string? Validity { get; set; }

    [JsonPropertyName("status")]
    public string? Status { get; set; }
}
