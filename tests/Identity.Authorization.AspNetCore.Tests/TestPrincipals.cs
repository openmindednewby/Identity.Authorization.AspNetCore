using System.Security.Claims;
using Identity.Abstractions.Authorization.Permissions;

namespace Identity.Authorization.AspNetCore.Tests;

internal static class TestPrincipals
{
    private const string AuthenticationType = "test";

    public static ClaimsPrincipal SignedIn(string role) =>
        new(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Role, role) }, AuthenticationType));

    public static PermissionMap Map(string[] permissions, params (string Role, string[] Permissions)[] grants) =>
        new(permissions, grants.ToDictionary(grant => grant.Role, grant => (IReadOnlyCollection<string>)grant.Permissions));
}

internal sealed class FixedBlockCheck : IBlockedPrincipalCheck
{
    private readonly bool _isBlocked;

    public FixedBlockCheck(bool isBlocked) => _isBlocked = isBlocked;

    public ClaimsPrincipal? CheckedUser { get; private set; }

    public CancellationToken ReceivedToken { get; private set; }

    public Task<bool> IsBlockedAsync(ClaimsPrincipal user, CancellationToken cancellationToken)
    {
        CheckedUser = user;
        ReceivedToken = cancellationToken;
        return Task.FromResult(_isBlocked);
    }
}
