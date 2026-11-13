using Identity.Abstractions.Authorization.Permissions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Identity.Authorization.AspNetCore;

public static class PermissionAuthorizationServiceCollectionExtensions
{
    /// <summary>Registers the permission map, the perm:name policy provider, both handlers and the startup check.</summary>
    public static IServiceCollection AddPermissionAuthorization(this IServiceCollection services, PermissionMap map)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(map);

        AddPolicyProvider(services);
        services.AddAuthorizationCore();
        services.TryAddSingleton(map);
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthorizationHandler, PermissionAuthorizationHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthorizationHandler, NotBlockedAuthorizationHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, PermissionAuthorizationStartupCheck>());
        return services;
    }

    private static void AddPolicyProvider(IServiceCollection services)
    {
        var existing = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(IAuthorizationPolicyProvider));
        var ours = ServiceDescriptor.Singleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();

        if (existing is null)
        {
            services.TryAdd(ours);
            return;
        }

        if (existing.ImplementationType == typeof(PermissionPolicyProvider))
        {
            return;
        }

        if (existing.ImplementationType != typeof(DefaultAuthorizationPolicyProvider))
        {
            var registered = existing.ImplementationType?.FullName ?? "a factory or instance";
            throw new InvalidOperationException(
                $"An IAuthorizationPolicyProvider ({registered}) is already registered; AddPermissionAuthorization cannot replace it.");
        }

        services.Replace(ours);
    }
}
