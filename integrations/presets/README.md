# Integration presets

The `preset_revision` field is the canonical policy revision for each shipped preset. It binds route behavior, DNS mode, redirect policy, query policy, and auth rendering behavior.

`auth.secret_handle` is intentionally excluded from the policy revision. The handles in this directory are illustrative only. Every launch document must replace them with a deployment-specific handle before lowering:

- `users/<launch_user>/...` for user-owned integration credentials; or
- `organizations/...` for credentials authorized later by scoped OpenBao identity/policy.

The route-policy lowerer still requires and validates `auth.secret_handle` independently, including matching `users/<launch_user>/...` handles to the launch `user_id`. Session/proxy-capability handles such as `sessions/...` are not valid integration credentials.

All other auth fields remain revision-bound, including header name, prefix, placeholder, and auth type.

These policy files do not advertise native client compatibility. Native npm remains unsupported until a separate launcher/proxy-agent decision is accepted and implemented.

Slice 2a route-policy lowering supports redirect `deny` only. The schema reserves `allow-declared` for a later slice, but shipped presets and the current lowerer reject it.
