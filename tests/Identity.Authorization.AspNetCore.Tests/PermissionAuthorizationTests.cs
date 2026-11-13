using System.Security.Claims;
using Identity.Abstractions.Authorization.Permissions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Shouldly;

namespace Identity.Authorization.AspNetCore.Tests;

public class PermissionAuthorizationTests
{
    [Fact]
    public async Task Authorize_WithRoleGrantingPermission_Succeeds()
    {
        using var provider = BuildServices(new[] { "funds.issue" }, ("finance-operator", new[] { "funds.issue" }));
        var user = TestPrincipals.SignedIn("finance-operator");

        var result = await Authorize(provider, user, resource: null, PermissionPolicy.For("funds.issue"));

        result.Succeeded.ShouldBeTrue();
    }

    [Fact]
    public async Task Authorize_WithoutRoleGrantingPermission_Fails()
    {
        using var provider = BuildServices(
            new[] { "deals.read", "funds.issue" },
            ("viewer", new[] { "deals.read" }));
        var user = TestPrincipals.SignedIn("viewer");

        var result = await Authorize(provider, user, resource: null, PermissionPolicy.For("funds.issue"));

        result.Succeeded.ShouldBeFalse();
    }

    [Fact]
    public async Task Authorize_WhenUserIsAnonymous_Fails()
    {
        using var provider = BuildServices(new[] { "deals.read" }, ("viewer", new[] { "deals.read" }));
        var user = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Role, "viewer") }));

        var result = await Authorize(provider, user, resource: null, PermissionPolicy.For("deals.read"));

        result.Succeeded.ShouldBeFalse();
    }

    [Fact]
    public async Task Authorize_WhenBlockCheckReportsBlocked_FailsDespitePermission()
    {
        var blockedCheck = new FixedBlockCheck(isBlocked: true);
        using var provider = BuildServices(new[] { "deals.read" }, ("viewer", new[] { "deals.read" }), blockedCheck);
        var user = TestPrincipals.SignedIn("viewer");

        var result = await Authorize(provider, user, resource: null, PermissionPolicy.For("deals.read"));

        result.Succeeded.ShouldBeFalse();
        result.Failure!.FailureReasons.ShouldContain(reason => reason.Message == "The principal is blocked.");
        blockedCheck.CheckedUser.ShouldBeSameAs(user);
    }

    [Fact]
    public async Task Authorize_WhenBlockCheckReportsNotBlocked_Succeeds()
    {
        using var provider = BuildServices(
            new[] { "deals.read" },
            ("viewer", new[] { "deals.read" }),
            new FixedBlockCheck(isBlocked: false));
        var user = TestPrincipals.SignedIn("viewer");

        var result = await Authorize(provider, user, resource: null, PermissionPolicy.For("deals.read"));

        result.Succeeded.ShouldBeTrue();
    }

    [Fact]
    public async Task Authorize_WithAbortedRequest_PassesRequestAbortedTokenToBlockCheck()
    {
        using var aborted = new CancellationTokenSource();
        await aborted.CancelAsync();
        var blockCheck = new FixedBlockCheck(isBlocked: false);
        using var provider = BuildServices(new[] { "deals.read" }, ("viewer", new[] { "deals.read" }), blockCheck);
        var httpContext = new DefaultHttpContext { RequestAborted = aborted.Token };

        await Authorize(provider, TestPrincipals.SignedIn("viewer"), httpContext, PermissionPolicy.For("deals.read"));

        blockCheck.ReceivedToken.ShouldBe(aborted.Token);
        blockCheck.ReceivedToken.IsCancellationRequested.ShouldBeTrue();
    }

    [Fact]
    public async Task Authorize_WithoutHttpContextResource_PassesNoneTokenToBlockCheck()
    {
        var blockCheck = new FixedBlockCheck(isBlocked: false);
        using var provider = BuildServices(new[] { "deals.read" }, ("viewer", new[] { "deals.read" }), blockCheck);

        await Authorize(provider, TestPrincipals.SignedIn("viewer"), resource: null, PermissionPolicy.For("deals.read"));

        blockCheck.ReceivedToken.CanBeCanceled.ShouldBeFalse();
    }

    [Fact]
    public async Task GetPolicyAsync_WithUndeclaredPermission_ReturnsNull()
    {
        using var provider = BuildServices(new[] { "deals.read" }, ("viewer", new[] { "deals.read" }));
        var policies = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policies.GetPolicyAsync(PermissionPolicy.For("funds.issue"));

        policy.ShouldBeNull();
    }

    [Fact]
    public async Task GetPolicyAsync_WithNamedNonPermissionPolicy_ReturnsConfiguredPolicy()
    {
        var services = new ServiceCollection().AddLogging();
        services.AddPermissionAuthorization(TestPrincipals.Map(new[] { "deals.read" }));
        services.Configure<AuthorizationOptions>(options =>
            options.AddPolicy("master-only", builder => builder.RequireRole("master")));
        using var provider = services.BuildServiceProvider();
        var policies = provider.GetRequiredService<IAuthorizationPolicyProvider>();

        var policy = await policies.GetPolicyAsync("master-only");

        policy.ShouldNotBeNull();
        policy.Requirements.ShouldNotContain(requirement => requirement is PermissionRequirement);
    }

    private static ServiceProvider BuildServices(
        string[] permissions,
        (string Role, string[] Permissions) grant,
        IBlockedPrincipalCheck? blockCheck = null)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddPermissionAuthorization(TestPrincipals.Map(permissions, grant));
        if (blockCheck is not null)
        {
            services.AddSingleton(blockCheck);
        }

        return services.BuildServiceProvider();
    }

    private static async Task<AuthorizationResult> Authorize(
        IServiceProvider provider,
        ClaimsPrincipal user,
        object? resource,
        string policy)
    {
        using var scope = provider.CreateScope();
        var authorization = scope.ServiceProvider.GetRequiredService<IAuthorizationService>();
        return await authorization.AuthorizeAsync(user, resource, policy);
    }
}
