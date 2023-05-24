using LazyCache;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Poort8.Ishare.Core.Tests;

[TestClass]
public class AuthenticationServiceTests
{
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
    private static Mock<IConfiguration> ConfigMock;
    private static Mock<ILogger<AuthenticationService>> LoggerMock;
    private static Mock<IHttpClientFactory> HttpClientFactoryMock;
    private static Mock<IAppCache> MemoryCacheMock;
    private static X509Certificate2 TestCertificate;
    private static X509Certificate2 TestRootCertificate;
    private static Mock<ICertificateProvider> CertificateProviderMock;
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.

    [ClassInitialize]
    public static void ClassInitialize(TestContext testContext)
    {
        ConfigMock = new Mock<IConfiguration>();
        ConfigMock
            .SetupGet(x => x[It.Is<string>(s => s == "ClientId")])
            .Returns("EU.EORI.NL888888881");

        LoggerMock = new Mock<ILogger<AuthenticationService>>();

        HttpClientFactoryMock = new Mock<IHttpClientFactory>();
        MemoryCacheMock = new Mock<IAppCache>();

        TestCertificate = new X509Certificate2("poort8.ishare.common.tests.pfx", "poort8.ishare.common.tests");
        TestRootCertificate = new X509Certificate2("poort8.ishare.common.tests.root.pfx", "poort8.ishare.common.tests");

        var chainArray = new List<string>()
        {
            Convert.ToBase64String(TestCertificate.GetRawCertData()),
            Convert.ToBase64String(TestRootCertificate.GetRawCertData())
        };

        CertificateProviderMock = new Mock<ICertificateProvider>();
        CertificateProviderMock.
            Setup(x => x.GetSigningCredentials()).Returns(new X509SigningCredentials(TestCertificate));
        CertificateProviderMock.
            Setup(x => x.GetChainString()).Returns(chainArray);
    }

    [TestMethod]
    public void TestCreateAndValidateTokenSuccess()
    {
        var authenticationService = new AuthenticationService(LoggerMock.Object, ConfigMock.Object, HttpClientFactoryMock.Object, MemoryCacheMock.Object, CertificateProviderMock.Object);
        var clientAssertion = authenticationService.CreateClientAssertion("EU.EORI.NL888888881");
        authenticationService.ValidateToken("EU.EORI.NL888888881", clientAssertion);

        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(clientAssertion);

        Assert.AreEqual("RS256", token.Header.Alg);
        Assert.AreEqual("JWT", token.Header.Typ);
        Assert.IsNotNull(token.Header.X5c);
        Assert.IsNotNull(token.Payload.Iss);
        Assert.AreEqual(token.Payload.Iss, token.Payload.Sub);
        Assert.IsNotNull(token.Payload.Aud);
        Assert.IsNotNull(token.Payload.Jti);
        Assert.IsNotNull(token.Payload.Iat);
        Assert.AreEqual(token.Payload.Iat, token.Payload.Nbf);
        Assert.AreEqual(token.Payload.Exp, token.Payload.Iat + 30);
    }

    [TestMethod]
    public void TestCreateAndValidateTokenWithClaimsSuccess()
    {
        var authenticationService = new AuthenticationService(LoggerMock.Object, ConfigMock.Object, HttpClientFactoryMock.Object, MemoryCacheMock.Object, CertificateProviderMock.Object);
        var obje = new { test = "testValue" };
        var additionalClaims = new List<Claim> { new Claim("testClaim", JsonSerializer.Serialize(obje), JsonClaimValueTypes.Json) };
        var informationToken = authenticationService.CreateTokenWithClaims(null, additionalClaims);
        authenticationService.ValidateToken("EU.EORI.NL888888881", informationToken, 30, true, false);

        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(informationToken);

        Assert.AreEqual("RS256", token.Header.Alg);
        Assert.AreEqual("JWT", token.Header.Typ);
        Assert.IsNotNull(token.Header.X5c);
        Assert.IsNotNull(token.Payload.Iss);
        Assert.AreEqual(token.Payload.Iss, token.Payload.Sub);
        Assert.IsNotNull(token.Payload.Jti);
        Assert.IsNotNull(token.Payload.Iat);
        Assert.AreEqual(token.Payload.Iat, token.Payload.Nbf);
        Assert.AreEqual(token.Payload.Exp, token.Payload.Iat + 30);
        Assert.AreEqual(token.Claims.Where(cl => cl.Type == additionalClaims.First().Type).First().Value, additionalClaims.First().Value);
    }

    [TestMethod]
    [ExpectedException(typeof(SecurityTokenInvalidAudienceException))]
    public void TestInvalidAudience()
    {
        var authenticationService = new AuthenticationService(LoggerMock.Object, ConfigMock.Object, HttpClientFactoryMock.Object, MemoryCacheMock.Object, CertificateProviderMock.Object);
        var clientAssertion = authenticationService.CreateClientAssertion("EU.EORI.FAIL");
        authenticationService.ValidateToken("NL.KVK.FAIL", clientAssertion);
    }

    [TestMethod]
    [ExpectedException(typeof(SecurityTokenInvalidIssuerException))]
    public void TestInvalidIssuer()
    {
        var authenticationService = new AuthenticationService(LoggerMock.Object, ConfigMock.Object, HttpClientFactoryMock.Object, MemoryCacheMock.Object, CertificateProviderMock.Object);
        var clientAssertion = authenticationService.CreateClientAssertion("EU.EORI.NL888888881");
        authenticationService.ValidateToken("EU.EORI.FAIL", clientAssertion);
    }
}
