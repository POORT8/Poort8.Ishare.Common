namespace Poort8.Ishare.Core;

public interface ISchemeOwnerService
{
    Task VerifyCertificateIsTrustedAsync(string? registrar, string clientAssertion);
    Task VerifyPartyAsync(string? registrar, string partyId, string clientAssertion);
}