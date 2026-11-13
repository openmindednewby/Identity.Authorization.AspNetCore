using Identity.Abstractions.Authorization.Permissions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace Identity.Authorization.AspNetCore;

public static class PermissionPolicyNames
{
    /// <summary>The perm:name policies the endpoints require whose permission the map does not declare.</summary>
    public static IReadOnlyList<string> FindUndeclared(IEnumerable<Endpoint> endpoints, PermissionMap map)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentNullException.ThrowIfNull(map);

        return endpoints
            .SelectMany(endpoint => endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>())
            .Select(data => data.Policy)
            .OfType<string>()
            .Where(policy => PermissionPolicy.TryGetPermission(policy, out var permission) && !map.IsDeclared(permission))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToList();
    }
}
