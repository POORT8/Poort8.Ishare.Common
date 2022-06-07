[![Actions Status](https://github.com/POORT8/Poort8.Ishare.Common/workflows/Build%20and%20test/badge.svg)](https://github.com/POORT8/Poort8.Ishare.Common/actions)

# Poort8.Ishare.Common
The project contains the *common endpoints* of the [iSHARE scheme](https://dev.ishareworks.org/):

 - [Access Token (M2M)](https://dev.ishareworks.org/common/token.html)
 - [Capabilities](https://dev.ishareworks.org/common/capabilities.html)

## Getting Started

 1. First you need to have an iSHARE test certificate. You can request one [here](https://dev.ishareworks.org/demo-and-testing/test-certificates.html).
 2. For now, the certificate is provided to the docker container as a (secret) environment variable. Extract the byte stream from the certificate file (p12 of pfx). For example using PowerShell:
```
$fileContentBytes = Get-Content <test-certificate.p12> -Encoding Byte -Raw
[System.Convert]::ToBase64String($fileContentBytes) | Out-File <test-certificate.p12-bytes.txt>
```
 3. Pull the docker container using:
```
docker pull ghcr.io/poort8/poort8.ishare.common:latest
```
 4. Set the following environment variables:
    - ClientId > Your EORI, for example: EU.EORI.NL888888881
    - SchemeOwnerUrl > Use the iSHARE scheme owner url of the test environment: https://scheme.isharetest.net
    - SchemeOwnerIdentifier > Use the EORI of the iSHARE scheme owner: EU.EORI.NL000000000
    - Certificate > Your iSHARE test certificate as a byte stream as created in step 2.
    - CertificatePassword > The password of the iSHARE test certificate.
    - CertificateChain > The certificates of the [iSHARE Test CA](https://dev.ishareworks.org/demo-and-testing/test-certificates.html#ishare-test-ca) as a comma separated byte stream. Use step 2 to get these. In case your certificate is issued by _C=NL, O=iSHARE Foundation, CN=TEST iSHARE Foundation PKIoverheid Organisatie Server CA - G3_, you can use [this](https://raw.githubusercontent.com/POORT8/Poort8.Ishare.Common/master/ishare-test-ca-chain.txt) chain.
    - CertificateChainPassword > Empty string for public test certificates: ""
    - IshareRole > Your role in the iSHARE scheme. Should be one of the following values: [Authorization Registry, Scheme Owner, Service Provider](https://ishareworks.atlassian.net/wiki/spaces/IS/pages/70222187/Glossary)
    - ApiVersion > The version of your iSHARE API
    - TokenEndpointId > A self chosen GUID to identify your token endpoint. You can generate one on [GuidGen](https://www.guidgen.com)
    - TokenEndpointUrl > The URL of your token endpoint. Usually your api address appended with /token
    - CapabilitiesEndpointId > A self chosen GUID to identify your capabilities endpoint. You can generate one on [GuidGen](https://www.guidgen.com)
    - CapabilitiesEndpointUrl > The URL of your capabilities endpoint. Usually your api address appended with /capabilities
    - PublicEndpoints > A semicolon separated string to represent all of your public iSHARE endpoints. The values of the endpoint itself are pipe separated, for example:
```
GUID-public-endpoint-1|name-public-endpoint-1|description-public-endpoint-1|https://endpoints.myapi.com/public-endpoint-1;GUID-public-endpoint-2|name-public-endpoint-2|description-public-endpoint-2|https://endpoints.myapi.com/public-endpoint-2
```
    - PrivateEndpoints > Like PublicEndpoints, a semicolon separated string to represent all of your private iSHARE endpoints, for example:
```
GUID-private-endpoint-1|name-private-endpoint-1|description-private-endpoint-1|https://endpoints.myapi.com/private-endpoint-1;GUID-private-endpoint-2|name-private-endpoint-2|description-private-endpoint-2|https://endpoints.myapi.com/private-endpoint-2
```

## Acknowledgements

This package was developed with partial funding from the Dutch Topsector Logistics.
