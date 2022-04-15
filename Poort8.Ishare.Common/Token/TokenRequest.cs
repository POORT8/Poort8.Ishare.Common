using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace Poort8.Ishare.Common.Token;

public class TokenRequest
{
    [Required]
    [BindProperty(Name = "grant_type")]
    public string GrantType { get; set; } = null!;

    [Required]
    [BindProperty(Name = "scope")]
    public string Scope { get; set; } = null!;

    [Required]
    [BindProperty(Name = "client_id")]
    public string ClientId { get; set; } = null!;

    [Required]
    [BindProperty(Name = "client_assertion_type")]
    public string ClientAssertionType { get; set; } = null!;

    [Required]
    [BindProperty(Name = "client_assertion")]
    public string ClientAssertion { get; set; } = null!;
}
