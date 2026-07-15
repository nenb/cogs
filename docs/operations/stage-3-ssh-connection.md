# Stage 3 S3-02 SSH connection foundation

Scope: IMPLEMENTATION §21.1 connection security foundation only. This does not implement `read`, `write`, `edit`, or `bash` behavior.

## Library selection

Selected library: `ssh2` exactly pinned at `1.17.0`.

Rationale:

- Actively maintained Node SSH client/server package with a small dependency surface.
- Supports host-key pinning through `hostHash: "sha256"` plus `hostVerifier`.
- Supports public-key authentication and explicit authentication method selection.
- Supports connection/handshake timeout configuration and algorithm overrides.
- License: MIT, compatible with this repository policy.
- Transitive production additions are permissive (`MIT`, `BSD-3-Clause`) except for a narrow exact `tweetnacl@0.14.5` `Unlicense` exception inherited through `bcrypt-pbkdf`; this is pinned and scoped in the license checker rather than globally allowing future `Unlicense` packages. The checker also records exact MIT overrides for legacy `licenses[]` metadata in `ssh2`, `cpu-features`, and `buildcheck`.
- `ssh2` may use optional native `cpu-features`/`nan` acceleration when install scripts are allowed. If optional native install is unavailable or scripts are ignored, `ssh2` falls back to its JavaScript path; Cogs does not depend on native acceleration for correctness or security in this slice.
- `npm audit --audit-level=high` is clean for the pinned lockfile at this slice.

Type package: `@types/ssh2` exactly pinned at `1.15.5` for TypeScript declarations.

## Security boundary

The S3-02 connection manager:

- consumes only trusted, validated runtime config;
- requires a `SHA256:` launch host-key pin;
- reads only the configured per-session client private-key file;
- requires that key file to be a bounded regular non-symlink file with restrictive permissions and reads at most the configured limit plus one byte from the opened descriptor;
- uses public-key authentication only;
- does not enable password, keyboard-interactive, agent, agent forwarding, X11, port forwarding, arbitrary subsystems, host-key prompts/auto-update, or local/system-command fallback;
- removes legacy algorithms where the library supports algorithm overrides;
- bounds connect, handshake, permit acquisition/queueing, and shutdown behavior;
- enforces a fair maximum concurrent permit count for future manager-owned exec/SFTP operations;
- supports `AbortSignal` cancellation;
- tears down fail-closed on disconnect/error/timeout;
- keeps the SSH client internals and private-key material out of public/API/event surfaces.

The real `ssh2` adapter authenticates the pinned connection. This slice exposes only permit/semaphore leases, not real SSH channels. Future §21.2 exec/SFTP methods must be manager-owned and hold these permits while they open and use real SSH/SFTP resources. Command execution and SFTP operations remain future §21 work.

The manager does not fail the worker merely because no tool is running. The §21 idle/progress timeout for active commands or file transfers is deferred to the next slice; SSH keepalives are used only for dead-peer detection at the transport layer.

## Lifecycle integration

`createSshLaunchDependency(...)` exposes a `LaunchDependency` named `ssh`. Launch readiness opens only after the pinned connection is authenticated. Callers wire the manager's `onLost` callback to `LaunchLifecycle.dependencyLost("ssh")` so disconnect/error/timeout revokes readiness.

## Evidence authority

Unit tests use dependency-injected fake transports for deterministic adversarial coverage plus a focused real-`ssh2` pre-ready terminal-event check. The label-gated `insecure-container` workflow runs a functional-only OpenSSH smoke against the production adapter using its generated loopback endpoint, per-session client key, and OpenSSH SHA256 host fingerprint; the correct pin must authenticate and a wrong pin must fail closed. This smoke does not execute Cogs tools and is non-authoritative for isolation. No AWS, EKS, release, or production claim is made.
