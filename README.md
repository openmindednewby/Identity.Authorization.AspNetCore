# Identity.Authorization.AspNetCore

ASP.NET Core wiring for the `Identity.Abstractions` permission model.

```bash
dotnet add package Identity.Authorization.AspNetCore
```

## Use

```csharp
var map = new PermissionMap(
    new[] { "deals.read", "funds.issue" },
    new Dictionary<string, IReadOnlyCollection<string>>
    {
        ["viewer"] = new[] { "deals.read" },
        ["finance-operator"] = new[] { "deals.read", "funds.issue" },
    });

builder.Services.AddPermissionAuthorization(map);
builder.Services.AddScoped<IBlockedPrincipalCheck, MyTenantBlockCheck>();
```

An endpoint requires `PermissionPolicy.For("funds.issue")` (`perm:funds.issue`). That policy is: signed in, not blocked (every registered `IBlockedPrincipalCheck`, given `HttpContext.RequestAborted`), and a role claim whose role grants the permission. All checks are authorization handlers, so they run before model binding.

- `RequireNotBlocked()` adds the not-blocked check to any policy, such as the default policy.
- `AddPermissionAuthorization` replaces only the default `IAuthorizationPolicyProvider`; any other provider already registered throws.
- At host start, before traffic, `PermissionAuthorizationStartupCheck` throws when the policy provider was replaced later or an endpoint requires a `perm:` name the map does not declare.

## Publish

```powershell
.\publish.ps1 -Bump minor
```
