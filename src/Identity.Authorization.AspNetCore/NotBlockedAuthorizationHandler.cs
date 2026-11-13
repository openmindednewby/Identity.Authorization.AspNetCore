using Identity.Abstractions.Authorization.Permissions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace Identity.Authorization.AspNetCore;

public sealed class NotBlockedAuthorizationHandler : AuthorizationHandler<NotBlockedRequirement>
{
    private readonly IEnumerable<IBlockedPrincipalCheck> _checks;

    public NotBlockedAuthorizationHandler(IEnumerable<IBlockedPrincipalCheck> checks)
    {
        ArgumentNullException.ThrowIfNull(checks);
        _checks = checks;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        NotBlockedRequirement requirement)
    {
        var cancellationToken = context.Resource is HttpContext httpContext
            ? httpContext.RequestAborted
            : CancellationToken.None;

        foreach (var check in _checks)
        {
            if (await check.IsBlockedAsync(context.User, cancellationToken))
            {
                context.Fail(new AuthorizationFailureReason(this, "The principal is blocked."));
                return;
            }
        }

        context.Succeed(requirement);
    }
}
