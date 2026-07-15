# ADR 0013: Allow a bounded Issue #64 line-budget exception for SSH bash

- Status: Accepted
- Date: 2026-07-15
- Decision owner: Nick Byrne
- Accepted by: Nick Byrne on 2026-07-15

## Context

`IMPLEMENTATION.md` §4 states that test code is outside the Cogs line-count budget and that production implementation should remain approximately 3,000–5,000 lines. Crossing 5,000 production lines requires a scope and architecture ADR rather than compressing security-sensitive code. `IMPLEMENTATION.md` §29 repeats this as a Stage 3 exit criterion: production code must remain in the 3,000–5,000-line planning range, or a scope/architecture ADR must explain and approve the deviation.

Issue [#64](https://github.com/nenb/cogs/issues/64) implements the Stage 3 SSH/SFTP sandbox tools from `IMPLEMENTATION.md` §21. PR #76 completed §21.1 connection security. PR #77 completed the SFTP `read`/`write`/`edit` portion of §21.2. The remaining issue #64 work includes production SSH-backed `bash`, including `/workspace` execution, streaming, cancellation, process-group termination, output truncation, exit/signal reporting, and adversarial §21.3 coverage.

A local draft of the bash slice was discarded before commit. That draft showed that a robust implementation needs additional production structure beyond the existing SFTP adapter:

- a narrow manager-owned SSH exec channel/port with no raw `ssh2` exposure to Pi-facing code;
- reconciled terminal handling across `exit`, `close`, and `error`;
- bounded process-group cancellation with confirmed terminal/close observation;
- bounded stdout/stderr sinks, UTF-8 handling, truncation metadata, and serialized Pi `onUpdate` publication;
- adversarial callback, malformed event, output, cancellation, disconnect, and cleanup handling comparable to the SFTP hardening already merged.

On clean `main` after PR #77 (`097f8f2`), production TypeScript under `src/` is 4,199 lines by:

```sh
find src -name '*.ts' -not -path '*/test/*' -print0 | xargs -0 wc -l | tail -1
```

Clean-main module inventory at `097f8f2`:

| Production module | Lines |
|---|---:|
| `src/api/server.ts` | 1,126 |
| `src/ssh/connection.ts` | 1,243 |
| `src/ssh/file-tools.ts` | 556 |
| `src/pi/session.ts` | 835 |
| `src/launch/lifecycle.ts` | 343 |
| `src/launch/config.ts` | 96 |
| **Total** | **4,199** |

The line-count budget includes production TypeScript under `src/`. It excludes tests, docs, scripts, deployment harnesses, and development-only utilities, including paths under `test/`, `docs/`, `scripts/`, `deploy/`, and `dev/`.

Completing the remaining issue #64 bash work without compressing security-sensitive code is likely to cross the 5,000-line planning threshold.

## Decision

Allow a bounded production line-count exception **only for issue #64**.

Until issue #64 is closed, production TypeScript under `src/` may grow up to **5,750 lines** for the SSH/SFTP tool work required by `IMPLEMENTATION.md` §21. This exception is limited to the issue #64 SSH/SFTP/bash scope and must not be used for unrelated Stage 3 features, model auth, egress integration, launch lifecycle, API expansion, AWS work, or release work.

Retain the current no-guest-daemon, modular trust-boundary adapter architecture. The SSH connection manager remains the boundary owner for SSH/SFTP channels, Pi-facing code receives narrow Cogs tool ports rather than raw `ssh2` clients/channels, and bash should be added as another bounded adapter in that architecture rather than by introducing a daemon or broader guest protocol.

Every PR using this exception must report the measured production `src/` TypeScript line count in its PR body or evidence notes. If completing issue #64 would exceed 5,750 production `src/` TypeScript lines, implementation must pause for another scope/architecture ADR before adding more production code.

After issue #64 is closed, this issue-specific exception is exhausted. Later deviations from the 3,000–5,000 planning range need their own ADR unless they are already covered by a separately accepted decision.

## Scope boundaries

This ADR does not approve:

- completion of issue #64 by itself;
- any `bash` implementation detail not reviewed in code;
- a custom guest daemon;
- a fallback from SSH to local tools, host shell, system `ssh`, filesystem access, or direct network access;
- PTY, stdin, agent forwarding, X11 forwarding, SSH agent use, or unrelated SSH features;
- AWS, EKS, production, release, or stronger Linux/KVM isolation claims;
- any detached-process cleanup claim without later implementation evidence that explicitly proves that behavior.

The implementation must preserve the existing Stage 3 authority boundary: insecure-container or local OpenSSH smoke tests are functional-only, while authoritative isolation/security claims require Linux/KVM evidence.

## Consequences

The remaining issue #64 work can proceed without forcing unsafe compression of SSH exec, cancellation, streaming, and adversarial-output handling. The guardrail is intentionally narrow: 5,750 production `src/` TypeScript lines, issue #64 only, with measured counts in affected PRs.

The issue #64 implementation remains responsible for satisfying the applicable `IMPLEMENTATION.md` §21 behavior and evidence requirements before the issue can close.

## Rejected alternatives

### Compress the bash implementation to stay below 5,000 lines

Rejected. The early draft review identified cleanup, terminal-state, streaming, callback, and malformed-event hardening that should not be omitted or compressed merely to satisfy the planning estimate.

### Split issue #64 into smaller PRs as the line-budget remedy

Rejected as a line-budget remedy. Smaller PRs may still be useful for review quality and risk control, but they do not change the aggregate production size needed to finish the issue #64 SSH bash behavior safely.

### Approve an unbounded Stage 3 line-count increase

Rejected. This ADR is deliberately limited to issue #64 and to 5,750 production `src/` TypeScript lines. Broader Stage 3 growth needs separate review.

### Introduce a custom guest daemon now

Rejected for this decision. A custom guest daemon would change the SSH/SFTP architecture and trigger a separate ADR under `IMPLEMENTATION.md` §47.
