# Stage 3 S3-02 partial evidence

Scope: S3-02 issue #64, IMPLEMENTATION §§21.1–21.2 SSH connection security foundation, SFTP `read`/`write`/`edit`, and initial SSH-backed `bash` port.

Implemented in this slice:

- Exact dependency pins: `ssh2@1.17.0` and `@types/ssh2@1.15.5`.
- MIT license/audit rationale documented in `docs/operations/stage-3-ssh-connection.md`.
- Narrow SSH connection manager with trusted runtime config validation, mandatory SHA256 host-key pin decoding/comparison, allocation-bounded private-key file loading/parsing, public-key-only authentication, bounded connect/handshake/SFTP-open/exec-open/permit-queue/shutdown behavior, fail-closed teardown, redacted errors, abortable fair permit acquisition, and launch-lifecycle `ssh` dependency integration.
- Production SFTP `read`/`write`/`edit` ports compatible with `CogsToolPorts`, using manager-owned bounded SFTP channels behind held permits.
- Production SSH-backed `bash` port using the no-guest-daemon modular adapter architecture accepted in ADR 0013, a fixed `/workspace` `/bin/bash --noprofile --norc` wrapper, bounded output/update/cancellation behavior, and manager-owned exec channels behind held permits.

Deterministic local tests cover:

- malformed/missing/wrong host-key pins and known OpenSSH SHA256 pin decoding to exact hex digest;
- wrong digest mismatch;
- symlink, directory, hard-link/replacement-risk, world-readable, oversized, missing, and malformed private-key files;
- auth failure and redacted errors/no private-key bytes;
- noncooperative connection timeout, prompt parent-abort cancellation when transports ignore the signal, and late-resolving connect cleanup;
- real `ssh2` wrapper pre-ready terminal rejection/no unhandled `error` listener gap;
- disconnect during active permit and readiness loss;
- SFTP path allowlists, traversal/control/NUL/Cf/NFC/surrogate rejection, realpath validation, symlink/directory/FIFO rejection, post-open `fstat` regular-file validation for read/edit, strict UTF-8 binary handling, oversize `encoding:"unknown"` handling, serialized-result bounds, 0-based offset/limit/trailing-newline/empty/EOF semantics, atomic write temp cleanup attempts, fsync/rename failure paths, edit duplicate/mismatch unchanged behavior, short/growing read rejection, operation/cleanup/close timeout, close-failure readiness revocation, late callback/open cleanup, and concurrent channel permit bounding;
- permit flood/fairness, queue capacity, queued abort, and acquisition timeout handling;
- double shutdown, noncooperative close deadline, and throwing injected `close`/`destroy`/`off` cleanup paths;
- late callbacks, numeric SFTP status mapping, generic redaction of unknown/proxy callback errors, asynchronous callback throw containment, partial/zero-byte read tuples, malformed handle/read/stat tuple rejection, and listener cleanup;
- exec channel exit+close reconciliation, malformed non-Buffer chunks, duplicate exit, close-without-exit, post-terminal signal rejection, and no early terminal before close;
- bash wrapper shape: outer wrapper is not `setsid`, child uses `setsid --wait`, child process group is `child=$!`, TERM/INT/HUP traps target only `-$child`, and command input rejects NUL/unpaired surrogates;
- bash separated stdout/stderr, nonzero exit `ok:false`, bounded output truncation, split multibyte UTF-8, invalid UTF-8 lossy metadata, valid U+FFFD handling, ANSI/C0 JSON inertness, full Pi update result shape, cross-update runtime API-key redaction for stdout/stderr chunks, total/idle-timeout confirmed cancellation without readiness poisoning, signaled terminal structured `ok:false` with readiness revocation, publisher failure cancellation with readiness revocation, update overflow suppression, serialized result bounds, and hard timeout abort during exec open;
- no local fallback path.

Functional-only OpenSSH smoke:

- Final post-edit local functional-only smoke passed on 2026-07-15 against the exact 5,207-line candidate after the Docker Desktop file-sharing cache was reset with an official bounded restart and a zero pre-smoke Cogs inventory.
- In the final successful cycle, each of `dev/insecure-sandbox/driver.sh create`, `dev/insecure-sandbox/driver.sh verify`, and `dev/insecure-sandbox/driver.sh destroy` ran once; all emitted `result":"pass"` for the `insecure-container` profile.
- Independent post-destroy inventory confirmed absence of state and labeled Docker resources: `.cogs-dev/insecure-sandbox` absent, container `cogs-insecure-ad03ca1a2ae2` absent, volume `cogs-insecure-workspace-ad03ca1a2ae2` absent, and no Docker resources remained with labels `dev.cogs.profile=insecure-container` and `dev.cogs.state=ad03ca1a2ae2`.
- The label-gated `insecure-container` workflow includes a production-adapter SSH/SFTP/bash smoke against its generated OpenSSH endpoint.
- The correct OpenSSH SHA256 host fingerprint must authenticate.
- SFTP read/write/edit must work against `/workspace`; mismatch/duplicate edit must leave content unchanged.
- Bash must run in `/workspace`, report stdout/stderr, and preserve nonzero exit status.
- Cleanup is bounded at the smoke driver level, and a wrong pin must fail closed.
- This is functional-only evidence, not isolation evidence.

Exclusions and boundaries:

- Issue #64 remains open pending final review/evidence for the complete S3-02/§21 scope.
- No authoritative Linux/KVM isolation claim is made here.
- Detached descendants are not claimed to be guaranteed cleaned without later evidence.
- No real Envoy/auth/export bundle integration beyond the SSH/SFTP/bash tool foundation.
- No AWS, EKS, production, release, or isolation claim.

Production line count under ADR 0013:

- Current production TypeScript under `src/`: 5,207 lines.
- Guardrail: issue #64 only, maximum 5,750 production `src/` TypeScript lines before another ADR.

Status: partial S3-02 evidence only; issue #64 remains open.
