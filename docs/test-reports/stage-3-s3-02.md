# Stage 3 S3-02 partial evidence

Scope: S3-02 issue #64, IMPLEMENTATION §21.1 SSH connection security foundation only.

Implemented in this slice:

- Exact dependency pins: `ssh2@1.17.0` and `@types/ssh2@1.15.5`.
- MIT license/audit rationale documented in `docs/operations/stage-3-ssh-connection.md`.
- Narrow SSH connection manager with trusted runtime config validation, mandatory SHA256 host-key pin decoding/comparison, allocation-bounded private-key file loading/parsing, public-key-only authentication, bounded connect/handshake/permit-queue/shutdown behavior, fail-closed teardown, redacted errors, abortable fair permit acquisition, and launch-lifecycle `ssh` dependency integration.

Deterministic local tests cover:

- malformed/missing/wrong host-key pins and known OpenSSH SHA256 pin decoding to exact hex digest;
- wrong digest mismatch;
- symlink, directory, hard-link/replacement-risk, world-readable, oversized, missing, and malformed private-key files;
- auth failure and redacted errors/no private-key bytes;
- noncooperative connection timeout, prompt parent-abort cancellation when transports ignore the signal, and late-resolving connect cleanup;
- real `ssh2` wrapper pre-ready terminal rejection/no unhandled `error` listener gap;
- disconnect during active permit and readiness loss;
- permit flood/fairness, queue capacity, queued abort, and acquisition timeout handling;
- double shutdown, noncooperative close deadline, and throwing injected `close`/`destroy`/`off` cleanup paths;
- late callbacks and listener cleanup;
- no local fallback path.

Exclusions:

- No `read`, `write`, `edit`, or `bash` implementation yet.
- No real SSH channel abstraction, SFTP file operations, or command execution; this slice exposes bounded permits only.
- No real SSH/Envoy/auth/export bundle integration beyond the connection foundation.
- No AWS, EKS, production, release, or isolation claim.
- The label-gated `insecure-container` workflow now includes a functional-only production-adapter SSH smoke against its generated OpenSSH endpoint: the correct OpenSSH SHA256 host fingerprint must authenticate, and a wrong pin must fail closed. This is not isolation evidence and does not execute Cogs tools.

Status: partial S3-02 evidence only; issue #64 remains open.
