using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core;

public interface ICertificateProvider
{
    public X509Certificate2 GetSigningCertificate();
    public X509SigningCredentials GetSigningCredentials();
    public X509Chain GetChain();
    public IEnumerable<string> GetChainString();
}