using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Shouldly;

namespace Identity.Authorization.AspNetCore.Tests;

public class AddPermissionAuthorizationTests
{
    [Fact]
    public void AddPermissionAuthorization_WithDefaultProviderRegistered_ReplacesItWithPermissionProvider()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddAuthorizationCore();

        services.AddPermissionAuthorization(TestPrincipals.Map(new[] { "deals.read" }));

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<IAuthorizationPolicyProvider>().ShouldBeOfType<PermissionPolicyProvider>();
    }

    [Fact]
    public void AddPermissionAuthorization_WithOtherProviderRegistered_Throws()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddSingleton<IAuthorizationPolicyProvider, OtherPolicyProvider>();

        Should.Throw<InvalidOperationException>(() =>
            services.AddPermissionAuthorization(TestPrincipals.Map(new[] { "deals.read" })));
    }

    [Fact]
    public async Task StartingAsync_WithEndpointRequiringUndeclaredPermission_ThrowsNamingIt()
    {
        using var provider = BuildServices(new[] { "deals.read" }, "perm:deals.read", "perm:funds.issue");
        var check = StartupCheck(provider);

        var error = await Should.ThrowAsync<InvalidOperationException>(() => check.StartingAsync(CancellationToken.None));

        error.Message.ShouldContain("perm:funds.issue");
        error.Message.ShouldNotContain("perm:deals.read");
    }

    [Fact]
    public async Task StartingAsync_WithEveryEndpointPermissionDeclared_Completes()
    {
        using var provider = BuildServices(new[] { "deals.read" }, "perm:deals.read", "master-only");
        var check = StartupCheck(provider);

        await Should.NotThrowAsync(() => check.StartingAsync(CancellationToken.None));
    }

    [Fact]
    public async Task StartingAsync_WhenProviderReplacedAfterRegistration_Throws()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddPermissionAuthorization(TestPrincipals.Map(new[] { "deals.read" }));
        services.AddSingleton<IAuthorizationPolicyProvider, OtherPolicyProvider>();
        using var provider = services.BuildServiceProvider();
        var check = StartupCheck(provider);

        await Should.ThrowAsync<InvalidOperationException>(() => check.StartingAsync(CancellationToken.None));
    }

    private static ServiceProvider BuildServices(string[] permissions, params string[] endpointPolicies)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddPermissionAuthorization(TestPrincipals.Map(permissions));
        var endpoints = endpointPolicies
            .Select(policy => new Endpoint(
                _ => Task.CompletedTask,
                new EndpointMetadataCollection(new AuthorizeAttribute(policy)),
                policy))
            .ToArray();
        services.AddSingleton<EndpointDataSource>(new DefaultEndpointDataSource(endpoints));
        return services.BuildServiceProvider();
    }

    private static PermissionAuthorizationStartupCheck StartupCheck(IServiceProvider provider) =>
        provider.GetServices<IHostedService>().OfType<PermissionAuthorizationStartupCheck>().Single();

    private sealed class OtherPolicyProvider : IAuthorizationPolicyProvider
    {
        public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName) => Task.FromResult<AuthorizationPolicy?>(null);

        public Task<AuthorizationPolicy> GetDefaultPolicyAsync() =>
            Task.FromResult(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

        public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => Task.FromResult<AuthorizationPolicy?>(null);
    }
}
