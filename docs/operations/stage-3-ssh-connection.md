# Stage 3 S3-02 SSH connection foundation

Scope: IMPLEMENTATION §§21.1–21.2 SSH connection foundation plus SFTP `read`/`write`/`edit` file-tool ports only. This does not implement `bash` behavior or claim §21.3/issue completion.

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

The real `ssh2` adapter authenticates the pinned connection. The manager exposes bounded permit/semaphore leases and manager-owned SFTP channel access; raw `ssh2` clients/channels are not exposed to Pi-facing code. Every real SFTP channel is opened only after a held `sftp` permit, so the configured maximum bounds actual concurrent SFTP channels. Command execution remains future §21.3 work.

The manager does not fail the worker merely because no tool is running. SFTP file operations have independent open, operation, idle, and close bounds. SSH keepalives are used only for dead-peer detection at the transport layer.

## SFTP file-tool contracts

`createSftpFileToolPorts(...)` returns production `read`, `write`, and `edit` ports compatible with `CogsToolPorts`.

- Paths use guest POSIX semantics only. Absolute paths must remain under `/workspace`, `/shared/skills`, or `/user/skills` for `read`; `write` and `edit` are restricted to `/workspace`. Relative paths are interpreted under `/workspace`. NUL/control characters, backslashes, traversal, normalization ambiguity, overlong paths, symlink components/targets, directories, FIFOs, devices, sockets, and metadata inconsistencies fail closed.
- `read` returns strict UTF-8 success as `{ ok: true, path, content, encoding: "utf8", offset, limit, linesReturned, totalLines, eof, truncated, bytesRead, sizeBytes }`. `offset` is 0-based line offset, matching the Pi-facing schema, and `limit` is the maximum returned lines. Empty files return zero lines; offset past EOF returns no lines with `eof: true`. A trailing newline is preserved when the selected complete-line range reaches that trailing newline. Invalid UTF-8/binary files return bounded `{ ok: false, encoding: "binary", reason: "invalid_utf8", ... }`; oversize files return bounded `{ ok: false, encoding: "unknown", reason: "too_large", ... }`. Reads validate the opened handle with `fstat`, require a regular file, are size-checked before allocation, bound the complete serialized result within the Pi session default using bounded complete-line truncation, and verify no file growth/trailing bytes before returning.
- `write` returns `{ ok, path, bytesWritten, atomic: true, fsync: "openssh" }`. Content is bounded UTF-8. The adapter writes to a cryptographically unpredictable exclusive temporary sibling, uploads bounded chunks, validates temp metadata, requires OpenSSH `fsync` and `posix-rename`, then atomically replaces the target in the same directory. Failures, cancellation, disconnects, and timeouts attempt bounded temp cleanup and never intentionally publish partial target contents; cleanup is not guaranteed after transport loss.
- `edit` performs a bounded strict-UTF-8 read, validates the opened handle with `fstat`, requires a regular file, requires nonempty `oldText`, requires exactly one occurrence, applies exact replacement only, then uses the same atomic write path. Missing or duplicate matches leave the target unchanged.

SFTP v3 cannot eliminate all guest-side TOCTOU races against a malicious root guest. These checks are file-tool correctness and containment controls for trusted launch roots; they are not a host-security boundary. Future `bash` will make all guest files accessible to the guest process, so these file tools make no false isolation or host-secret claim.

## Lifecycle integration

`createSshLaunchDependency(...)` exposes a `LaunchDependency` named `ssh`. Launch readiness opens only after the pinned connection is authenticated. Callers wire the manager's `onLost` callback to `LaunchLifecycle.dependencyLost("ssh")` so disconnect/error/timeout revokes readiness.

## Evidence authority

Unit tests use dependency-injected fake transports/SFTP channels for deterministic adversarial coverage plus focused real-`ssh2` terminal-event checks, including numeric SFTP status mapping, generic redaction of unknown callback errors, callback throw containment, EOF/partial-read tuple handling, malformed metadata/handle/tuple rejection, post-open metadata validation, bounded operation/close/cleanup paths, close-failure readiness revocation, late exclusive-open cleanup, path/content validation, edit uniqueness, and permit bounding. The label-gated `insecure-container` workflow runs a functional-only OpenSSH smoke against the production adapter using its generated loopback endpoint, per-session client key, and OpenSSH SHA256 host fingerprint; the correct pin must authenticate, SFTP read/write/edit must work against `/workspace`, mismatch/duplicate edit must leave content unchanged, and a wrong pin must fail closed. This smoke does not execute bash and is non-authoritative for isolation. No AWS, EKS, release, or production claim is made.
