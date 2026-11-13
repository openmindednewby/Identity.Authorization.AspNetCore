using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Shouldly;

namespace Identity.Authorization.AspNetCore.Tests;

public class PermissionPolicyNamesTests
{
    [Fact]
    public void FindUndeclared_WithRepeatedUndeclaredPolicy_ReturnsItOnce()
    {
        var map = TestPrincipals.Map(new[] { "deals.read" });
        var endpoints = new[] { Endpoint("perm:funds.issue"), Endpoint("perm:funds.issue"), Endpoint("perm:deals.read") };

        var undeclared = PermissionPolicyNames.FindUndeclared(endpoints, map);

        undeclared.ShouldBe(new[] { "perm:funds.issue" });
    }

    [Fact]
    public void FindUndeclared_WithNonPermissionPolicies_ReturnsEmpty()
    {
        var map = TestPrincipals.Map(new[] { "deals.read" });
        var endpoints = new[] { Endpoint("master-only"), Endpoint("perm:") };

        var undeclared = PermissionPolicyNames.FindUndeclared(endpoints, map);

        undeclared.ShouldBeEmpty();
    }

    private static Endpoint Endpoint(string policy) =>
        new(_ => Task.CompletedTask, new EndpointMetadataCollection(new AuthorizeAttribute(policy)), policy);
}
