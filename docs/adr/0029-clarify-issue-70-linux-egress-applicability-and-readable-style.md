# ADR 0029: Clarify issue #70 Linux egress applicability and readable style

- Status: Accepted
- Date: 2026-07-19
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

ADR 0027 authorized the issue #70 development launcher as local development tooling with exact profiles, no fallback, and reuse of the reviewed Stage 3 Envoy/OpenBao/runtime-manager path. ADR 0028 superseded only ADR 0027's numeric launcher line cap and explicitly kept the preferred 7,200-line target and 7,800-line hard stop so security validation and cleanup code would not need to be compressed.

The Envoy egress composition slice wires the launcher to production egress components. Those components write private runtime material under the exact production material directory `/run/cogs/egress`. The launcher adapter therefore requires `/run/cogs/egress` to be a canonical, empty, mode `0700`, current-user-owned Linux tmpfs before and after runtime-manager use. This preserves the reviewed material boundary and cleanup proof, but it also means native macOS cannot complete full egress composition today.

The first version of the adapter compressed TypeScript style to remain under an obsolete narrower per-slice target. That reduced readability of security-critical validation even though ADR 0028 already authorized contingency for explicit, readable code.

## Decision

Full trusted Envoy egress composition for issue #70 currently requires a Linux host. The production material writer's exact `/run/cogs/egress` tmpfs prerequisite is required for every full `create` path that reaches Envoy egress composition, including the functional-only `insecure-container` profile.

Native macOS cannot complete full `create` today, including `insecure-container`, because it cannot satisfy the Linux tmpfs prerequisite natively. Developers should use Linux CI, a Linux workstation, or a Linux VM for full launcher egress composition. This is an explicit prerequisite failure, not a fallback path, product authority claim, or bug in the profile boundary.

The profile boundaries remain unchanged:

- `insecure-container` remains functional-only on a qualifying Linux host;
- `linux-kvm` remains the sole authoritative local security profile;
- `macos-vm` remains optional absent-fail, and full egress composition is unsupported natively on macOS at this stage;
- no profile fallback, local-tool fallback, open egress, anonymous auth, hidden `sudo` mount, egress bypass, or weakened tmpfs check is authorized.

ADR 0028's contingency must be used to keep security-critical launcher code readable. The preferred issue #70 launcher target remains at or below 7,200 non-test `dev/launcher/**/*.{ts,sh}` lines and the hard stop remains 7,800. Code should use normal repository style with descriptive names and ordinary control flow rather than compression to bank lines.

## Consequences

Launcher documentation must state the host applicability matrix and the Linux `/run/cogs/egress` tmpfs prerequisite before any full create/smoke evidence claim.

This ADR does not expand issue #70 scope. It does not authorize cloud, AWS, production daemon, scheduler, production authentication service, workflow/release/deploy behavior, new production dependencies, or changes to production egress material semantics.

Until later work adds an explicitly reviewed macOS VM driver or another reviewed trusted material strategy, native macOS remains unsuitable for full Envoy egress composition. Tests may continue using seams to validate adapter wiring and cleanup behavior, but such tests are not real launcher Envoy smoke evidence.
