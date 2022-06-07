using System.Text.Json.Serialization;

namespace Poort8.Ishare.Common.Capabilities;

public class CapabilitiesResponse
{
	[JsonPropertyName("capabilities_token")]
	public string CapabilitiesToken { get; set; }

    public CapabilitiesResponse(string capabilitiesToken)
	{
		CapabilitiesToken = capabilitiesToken;
	}
}