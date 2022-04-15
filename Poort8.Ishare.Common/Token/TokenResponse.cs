using System.Text.Json.Serialization;

namespace Poort8.Ishare.Common.Token;

public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; } = "Bearer";

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; } = 3600;

    public TokenResponse(string accessToken)
    {
        AccessToken = accessToken;
    }
}
