using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Poort8.Ishare.Core.Tests;

[TestClass]
public class CertificateProviderTests
{
    [TestMethod]
    public void TestConstructor()
    {
        var testPassword = "poort8.ishare.common.tests";
        var testCertificate = new X509Certificate2("poort8.ishare.common.tests.pfx", testPassword);
        var testRootCertificate = new X509Certificate2("poort8.ishare.common.tests.root.pfx", testPassword);

        var configMock = new Mock<IConfiguration>();
        configMock
            .SetupGet(x => x[It.Is<string>(s => s == "Certificate")])
            .Returns(Convert.ToBase64String(testCertificate.GetRawCertData()));
        configMock
            .SetupGet(x => x[It.Is<string>(s => s == "CertificatePassword")])
            .Returns(testPassword);
        configMock
            .SetupGet(x => x[It.Is<string>(s => s == "CertificateChain")])
            .Returns(Convert.ToBase64String(testRootCertificate.GetRawCertData()));
        configMock
            .SetupGet(x => x[It.Is<string>(s => s == "CertificateChainPassword")])
            .Returns(testPassword);

        var loggerMock = new Mock<ILogger<CertificateProvider>>();

        var certificateProvider = new CertificateProvider(loggerMock.Object, configMock.Object);
        Assert.IsNotNull(certificateProvider.GetSigningCertificate());
        Assert.IsNotNull(certificateProvider.GetChain());
        Assert.AreEqual(2, certificateProvider.GetChain().ChainElements.Count);
        Assert.AreEqual(2, certificateProvider.GetChainString().ToList().Count);
    }
}
