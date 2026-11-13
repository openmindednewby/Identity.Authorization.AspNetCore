using Microsoft.AspNetCore.Authorization;

namespace Identity.Authorization.AspNetCore;

public static class NotBlockedPolicyBuilderExtensions
{
    /// <summary>Adds the not-blocked requirement to a policy, such as a product's default policy.</summary>
    public static AuthorizationPolicyBuilder RequireNotBlocked(this AuthorizationPolicyBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddRequirements(new NotBlockedRequirement());
    }
}
