using Poort8.Ishare.Core;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace Poort8.Ishare.Common.Capabilities;

[Route("[controller]")]
[ApiController]
public class CapabilitiesController : ControllerBase
{
	private readonly ILogger<CapabilitiesController> _logger;
    private readonly IConfiguration _configuration;
    private readonly IAuthenticationService _authenticationService;

    public CapabilitiesController(
		ILogger<CapabilitiesController> logger,
        IConfiguration configuration,
        IAuthenticationService authenticationService)
	{
		_logger = logger;
        _configuration = configuration;
        _authenticationService = authenticationService;
	}

	//TODO: Swagger
	[HttpGet]
	[Produces("application/json")]
	[ProducesResponseType(StatusCodes.Status200OK)]
	[ProducesResponseType(StatusCodes.Status400BadRequest)]
	[ProducesResponseType(StatusCodes.Status401Unauthorized)]
	public IActionResult Get()
	{
		_logger.LogInformation("CapabilitiesRequest received");

        var authorization = Request.Headers.Authorization;

        var errorResponse = HandleAuthorization(authorization, out string? audience);
        if (errorResponse is not null) return errorResponse;

        var capabilitiesInfo = new CapabilitiesInfo(_configuration["ClientId"]!, new List<string> { _configuration["IshareRole"]! }, _configuration["ApiVersion"]!);
        var publicEndpoints = new List<Endpoint>
        {
            new Endpoint(_configuration["TokenEndpointId"]!, "access token", "Obtains access token", _configuration["TokenEndpointUrl"]!),
            new Endpoint(_configuration["CapabilitiesEndpointId"]!, "capabilities", "Retrieves iSHARE capabilities", _configuration["CapabilitiesEndpointUrl"]!, _configuration["TokenEndpointUrl"]!)
        };
        publicEndpoints.AddRange(RetrieveEndpointsFromConfig(_configuration["PublicEndpoints"]!));
        capabilitiesInfo.SupportedVersions.First().SupportedFeatures.Add(new PublicEndpoints(publicEndpoints));

        if (audience is not null)
        {
            capabilitiesInfo.SupportedVersions.First().SupportedFeatures.Add(new RestrictedEndpoints(RetrieveEndpointsFromConfig(_configuration["PrivateEndpoints"]!)));
        }
        var additionalClaims = new List<Claim> { new Claim("capabilities_info", JsonSerializer.Serialize(capabilitiesInfo), JsonClaimValueTypes.Json) };

        var token = _authenticationService.CreateTokenWithClaims(audience!, additionalClaims);
        var capabilitiesResponse = new CapabilitiesResponse(token);
		return new OkObjectResult(capabilitiesResponse);
	}

    private List<Endpoint> RetrieveEndpointsFromConfig(string configValue)
    {
        var endpoints = new List<Endpoint>();
        foreach (var endpoint in configValue.Split(';'))
        {
            var endpointProperties = endpoint.Split('|');
            if (endpointProperties?.Length == 4)
            {
                endpoints.Add(new Endpoint(endpointProperties[0], endpointProperties[1], endpointProperties[2], endpointProperties[3], _configuration["TokenEndpointUrl"]!));
            }
        }
        return endpoints;
    }

    private IActionResult? HandleAuthorization(StringValues authorization, out string? audience)
    {
        audience = null;
        if (string.IsNullOrEmpty(authorization)) return null;
        if (authorization.Count != 1 || authorization[0]?.StartsWith("Bearer ") != true)
        {
            return new BadRequestObjectResult("Invalid token format: not a bearer token");
        }

        var token = authorization[0]!.Replace("Bearer ", "");

        try
        {
            _authenticationService.ValidateAuthorizationHeader(_configuration["ClientId"]!, authorization);
        }
        catch (Exception e)
        {
            _logger.LogWarning("Invalid authorization header, further checks needed. Message: {msg}", e.Message);
            return new UnauthorizedObjectResult("Invalid bearer token");
        }

        var jwtToken = new JwtSecurityTokenHandler().ReadJwtToken(token);
        audience = jwtToken.Claims.Where(c => c.Type == "aud").First().Value;

        _logger.LogInformation("Valid authentication and authorization.");
        return null;
    }
}