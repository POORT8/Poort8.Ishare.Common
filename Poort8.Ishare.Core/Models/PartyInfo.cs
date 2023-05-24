using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core.Models;

public class PartyInfo
{
    [JsonPropertyName("party_id")]
    public string? PartyId { get; set; }

    [JsonPropertyName("party_name")]
    public string? PartyName { get; set; }

    [JsonPropertyName("adherence")]
    public AdherenceObject? Adherence { get; set; }

    [JsonPropertyName("certifications")]
    public List<Certification>? Certifications { get; set; }

    [JsonPropertyName("capability_url")]
    public string? CapabilityUrl { get; set; }

    public class AdherenceObject
    {
        [JsonPropertyName("status")]
        public string? Status { get; set; }

        [JsonPropertyName("start_date")]
        public DateTime StartDate { get; set; }

        [JsonPropertyName("end_date")]
        public DateTime EndDate { get; set; }
    }

    public class Certification
    {
        [JsonPropertyName("role")]
        public string? Role { get; set; }

        [JsonPropertyName("start_date")]
        public DateTime StartDate { get; set; }

        [JsonPropertyName("end_date")]
        public DateTime EndDate { get; set; }

        [JsonPropertyName("loa")]
        public int Loa { get; set; }
    }
}
