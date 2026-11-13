using Identity.Abstractions.Authorization.Permissions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Hosting;

namespace Identity.Authorization.AspNetCore;

public sealed class PermissionAuthorizationStartupCheck : IHostedLifecycleService
{
    private readonly IAuthorizationPolicyProvider _policyProvider;
    private readonly PermissionMap _map;
    private readonly IEnumerable<EndpointDataSource> _endpointSources;

    public PermissionAuthorizationStartupCheck(
        IAuthorizationPolicyProvider policyProvider,
        PermissionMap map,
        IEnumerable<EndpointDataSource> endpointSources)
    {
        ArgumentNullException.ThrowIfNull(policyProvider);
        ArgumentNullException.ThrowIfNull(map);
        ArgumentNullException.ThrowIfNull(endpointSources);
        _policyProvider = policyProvider;
        _map = map;
        _endpointSources = endpointSources;
    }

    /// <summary>Stops the host before it serves traffic when the provider was replaced or an endpoint names an undeclared permission.</summary>
    public Task StartingAsync(CancellationToken cancellationToken)
    {
        if (_policyProvider is not PermissionPolicyProvider)
        {
            throw new InvalidOperationException(
                $"IAuthorizationPolicyProvider is {_policyProvider.GetType().FullName}; AddPermissionAuthorization needs {nameof(PermissionPolicyProvider)}.");
        }

        var undeclared = PermissionPolicyNames.FindUndeclared(
            _endpointSources.SelectMany(source => source.Endpoints),
            _map);

        if (undeclared.Count > 0)
        {
            throw new InvalidOperationException(
                $"Endpoints require permissions the PermissionMap does not declare: {string.Join(", ", undeclared)}.");
        }

        return Task.CompletedTask;
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
