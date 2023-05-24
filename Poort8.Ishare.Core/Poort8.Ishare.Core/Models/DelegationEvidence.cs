using System.Text.Json.Serialization;

namespace Poort8.Ishare.Core.Models;

public class DelegationEvidence
{
    [JsonPropertyName("notBefore")]
    public int NotBefore { get; set; }

    [JsonPropertyName("notOnOrAfter")]
    public int NotOnOrAfter { get; set; }

    [JsonPropertyName("policyIssuer")]
    public string? PolicyIssuer { get; set; }

    [JsonPropertyName("target")]
    public TargetObject? Target { get; set; }

    [JsonPropertyName("policySets")]
    public List<PolicySet>? PolicySets { get; set; }

    public class PolicySet
    {
        [JsonPropertyName("maxDelegationDepth")]
        public int MaxDelegationDepth { get; set; }

        [JsonPropertyName("target")]
        public TargetObject? Target { get; set; }

        [JsonPropertyName("policies")]
        public List<Policy>? Policies { get; set; }
    }

    public class Policy
    {
        [JsonPropertyName("target")]
        public TargetObject? Target { get; set; }

        [JsonPropertyName("rules")]
        public List<Rule>? Rules { get; set; }
    }

    public class Rule
    {
        [JsonPropertyName("effect")]
        public string? Effect { get; set; }
    }

    public class Resource
    {
        [JsonPropertyName("type")]
        public string? Type { get; set; }

        [JsonPropertyName("identifiers")]
        public List<string>? Identifiers { get; set; }

        [JsonPropertyName("attributes")]
        public List<string>? Attributes { get; set; }
    }

    public class Environment
    {
        [JsonPropertyName("licenses")]
        public List<string>? Licenses { get; set; }

        [JsonPropertyName("serviceProviders")]
        public List<string>? ServiceProviders { get; set; }
    }

    public class TargetObject
    {
        [JsonPropertyName("accessSubject")]
        public string? AccessSubject { get; set; }

        [JsonPropertyName("environment")]
        public Environment? Environment { get; set; }

        [JsonPropertyName("resource")]
        public Resource? Resource { get; set; }

        [JsonPropertyName("actions")]
        public List<string>? Actions { get; set; }
    }
}
