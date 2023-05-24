using Microsoft.Extensions.DependencyInjection;

namespace Poort8.Ishare.Core;

public static class ServicesConfiguration
{
    public static void AddIshareCoreServices(this IServiceCollection services)
    {
        services.AddSingleton<ICertificateProvider, CertificateProvider>();
        services.AddSingleton<IAuthenticationService, AuthenticationService>();
        services.AddSingleton<ISchemeOwnerService, SchemeOwnerService>();
        services.AddSingleton<IPolicyEnforcementPoint, PolicyEnforcementPoint>();
    }
}
