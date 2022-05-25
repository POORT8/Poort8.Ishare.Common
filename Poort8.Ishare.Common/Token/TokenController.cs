using Microsoft.AspNetCore.Mvc;
using Poort8.Ishare.Core;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace Poort8.Ishare.Common.Token;

[Route("api/[controller]")]
[ApiController]
public class TokenController : ControllerBase
{
    private readonly ILogger<TokenController> _logger;
    private readonly IAuthenticationService _authenticationService;
    private readonly ISchemeOwnerService _schemeOwnerService;

    public TokenController(
        ILogger<TokenController> logger,
        IAuthenticationService authenticationService,
        ISchemeOwnerService schemeOwnerService)
    {
        _logger = logger;
        _authenticationService = authenticationService;
        _schemeOwnerService = schemeOwnerService;
    }

    //TODO: Swagger
    [HttpPost]
    [Consumes("application/x-www-form-urlencoded")]
    [Produces("application/json")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Post([Required, FromForm] TokenRequest request)
    {
        _logger.LogInformation("TokenRequest from {clientId}: {request}", request.ClientId, JsonSerializer.Serialize(request));

        if (request.GrantType != "client_credentials" ||
            request.Scope != "iSHARE" ||
            request.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        {
            return new BadRequestObjectResult("Invalid grant_type, scope or client_assertion_type.");
        }

        try
        {
            _authenticationService.ValidateToken(request.ClientId, request.ClientAssertion, 30, false);
        }
        catch (Exception e)
        {
            _logger.LogWarning("Returning bad request: invalid client_assertion. {msg}", e.Message);
            return new BadRequestObjectResult("Invalid client_assertion.");
        }

        try
        {
            await _schemeOwnerService.VerifyCertificateIsTrustedAsync(request.ClientAssertion);
        }
        catch (Exception e)
        {
            _logger.LogWarning("Returning bad request: certificate chain is not trusted. {msg}", e.Message);
            return new BadRequestObjectResult("Certificate chain is not trusted.");
        }

        try
        {
            await _schemeOwnerService.VerifyPartyAsync(request.ClientId, request.ClientAssertion);
        }
        catch (Exception e)
        {
            _logger.LogWarning("Returning bad request: failed party checks. {msg}", e.Message);
            return new BadRequestObjectResult("Failed party checks.");
        }

        try
        {
            var token = _authenticationService.CreateAccessToken(request.ClientId);
            var tokenResponse = new TokenResponse(token);

            _logger.LogInformation("Returning ok with token response {token}", token);
            return new OkObjectResult(tokenResponse);
        }
        catch (Exception e)
        {
            _logger.LogCritical("Returning internal server error. {msg}", e.Message);
            return StatusCode(StatusCodes.Status500InternalServerError);
        }
    }
}
