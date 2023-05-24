namespace Poort8.Ishare.Core;

public interface ISchemeOwnerService
{
    Task VerifyCertificateIsTrustedAsync(string clientAssertion);
    Task VerifyPartyAsync(string partyId, string clientAssertion);
}