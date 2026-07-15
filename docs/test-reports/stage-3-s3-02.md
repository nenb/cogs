# Stage 3 S3-02 partial evidence

Scope: S3-02 issue #64, IMPLEMENTATION §§21.1–21.2 SSH connection security foundation plus SFTP `read`/`write`/`edit` only.

Implemented in this slice:

- Exact dependency pins: `ssh2@1.17.0` and `@types/ssh2@1.15.5`.
- MIT license/audit rationale documented in `docs/operations/stage-3-ssh-connection.md`.
- Narrow SSH connection manager with trusted runtime config validation, mandatory SHA256 host-key pin decoding/comparison, allocation-bounded private-key file loading/parsing, public-key-only authentication, bounded connect/handshake/SFTP-open/permit-queue/shutdown behavior, fail-closed teardown, redacted errors, abortable fair permit acquisition, and launch-lifecycle `ssh` dependency integration.
- Production SFTP `read`/`write`/`edit` ports compatible with `CogsToolPorts`, using manager-owned bounded SFTP channels behind held permits.

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
- no local fallback path.

Exclusions:

- No `bash` implementation yet.
- No command execution, process groups, streaming command output, or §21.3 claim.
- No real SSH/Envoy/auth/export bundle integration beyond the connection and SFTP file-tool foundation.
- No AWS, EKS, production, release, or isolation claim.
- The label-gated `insecure-container` workflow includes a functional-only production-adapter SSH/SFTP smoke against its generated OpenSSH endpoint: the correct OpenSSH SHA256 host fingerprint must authenticate, read/write/edit must work against `/workspace`, mismatch/duplicate edit must leave content unchanged, cleanup is bounded at the smoke driver level, and a wrong pin must fail closed. This is not isolation evidence and does not execute bash.

Status: partial S3-02 evidence only; issue #64 remains open.
