using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core;

public class CertificateProvider : ICertificateProvider
{
    private readonly X509Certificate2 _certificate;
    private readonly X509Certificate2Collection _chainCertificates;

    public CertificateProvider(ILogger<CertificateProvider> logger, IConfiguration configuration)
    {
        try
        {
            _certificate = new X509Certificate2(
                Convert.FromBase64String(configuration["Certificate"]!),
                string.IsNullOrEmpty(configuration["CertificatePassword"]) ? null : configuration["CertificatePassword"]);

            _chainCertificates = new X509Certificate2Collection();
            var chain = configuration["CertificateChain"]!.Split(',');
            foreach (var certificate in chain)
            {
                _chainCertificates.Add(new X509Certificate2(Convert.FromBase64String(certificate), string.IsNullOrEmpty(configuration["CertificateChainPassword"]) ? null : configuration["CertificateChainPassword"]));
            }
        }
        catch (Exception)
        {
            logger.LogError("Could not create the certificate from configuration.");
            throw;
        }
    }

    public X509Certificate2 GetSigningCertificate()
    {
        return _certificate;
    }

    public X509SigningCredentials GetSigningCredentials()
    {
        return new X509SigningCredentials(_certificate);
    }

    public X509Chain GetChain()
    {
        var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(_chainCertificates);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        var isVerified = chain.Build(_certificate);

        if (!isVerified) { throw new Exception("Certificate chain is not verified."); }

        return chain;
    }

    public IEnumerable<string> GetChainString()
    {
        var chain = GetChain();
        return chain.ChainElements.Select(c => Convert.ToBase64String(c.Certificate.GetRawCertData()));
    }
}
