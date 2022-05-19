using Poort8.Ishare.Core;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Primitives;
using System.IdentityModel.Tokens.Jwt;

namespace Poort8.Ishare.Common.Capabilities;

[Route("api/[controller]")]
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
	public async Task<IActionResult> Get()
	{
		_logger.LogInformation("CapabilitiesRequest received");

        var authorization = Request.Headers.Authorization;

        var errorResponse = HandleAuthorization(authorization, out string audience);
        if (errorResponse is not null) return errorResponse;

        var token = _authenticationService.CreateClientAssertion(audience);

        var capabilitiesResponse = new CapabilitiesResponse(token);
		return new OkObjectResult(capabilitiesResponse);
	}

    private IActionResult? HandleAuthorization(StringValues authorization, out string audience)
    {
        audience = null;
        if (string.IsNullOrEmpty(authorization)) return null;
        if (authorization.Count != 1 || !authorization[0].StartsWith("Bearer "))
        {
            return new BadRequestObjectResult("Invalid token format");
        }

        var token = authorization[0].Replace("Bearer ", "");

        try
        {
            _authenticationService.ValidateAuthorizationHeader(_configuration["ClientId"], authorization);
        }
        catch (Exception e)
        {
            _logger.LogWarning("Invalid authorization header, further checks needed. Message: {msg}", e.Message);
            try
            {
                _authenticationService.ValidateToken(_configuration["ClientId"], authorization[0].Replace("Bearer ", ""), int.MaxValue, false, false);
                return new UnauthorizedObjectResult("Token has expired.");
            }
            catch
            {
                return new BadRequestObjectResult("Invalid token format");
            }
        }

        var jwtHandler = new JwtSecurityTokenHandler();
        var jwtToken = jwtHandler.ReadJwtToken(token);
        audience = jwtToken.Claims.Where(c => c.Type == "aud").First().Value;

        _logger.LogInformation("Valid authentication and authorization.");
        return null;
    }
}