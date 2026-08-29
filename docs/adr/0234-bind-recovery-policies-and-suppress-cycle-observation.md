# ADR 0234: Bind recovery policies and suppress cycle observation

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-29

Strict fresh retained state exposed two recovery-only defects after ADR 0231 made executable claims lazy.

First, the lazy process path still expected the historical tuple return from static role consumption and recomputed a different closure digest. Consume the exact `ExecutableRoleDescription`, validate its typed role/object set, and use its already authenticated contract closure digest. Recovery eagerly claims and immediately releases only the always-live ssh and ssh-keygen roles before journal parsing, thereby installing the exact dynamic policies needed to authenticate historical command records. Runtime roles remain lazy and removed containerd/ctr paths are not reopened without phase need.

Second, cleanup command supervision attempted to read cycle-route evidence from a recovery cleanup capability after process release. Recovery can never mint or extend cycle evidence. Detect the exact sealed production-recovery capability before effects and set its command marker route to `None`; ordinary production authority still requires the normal cycle-route accessor.

Any wrong closure, unavailable host role, malformed journal policy, non-recovery capability, descriptor close error, or command uncertainty fails closed. Focused admission, process, runtime, bridge, coordinator, TypeScript, formatting, and retained-line matrices pass.

This grants no AWS, provider, deployment, campaign, production, release, qualification, or promotion authority.
