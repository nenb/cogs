# ADR 0013: Proposed bounded Issue #64 line-budget gate for SSH bash

- Status: Proposed
- Date: 2026-07-15
- Decision owner: Nick Byrne

## Context

`IMPLEMENTATION.md` §4 Technology baseline sets the planning baseline that Cogs production implementation should remain approximately 3,000–5,000 lines, with tests outside that production-code budget. It also requires a scope and architecture ADR before crossing the 5,000 production-line planning threshold rather than compressing security-sensitive code to fit an estimate. `IMPLEMENTATION.md` §29 Stage 3 exit criteria carries that same gate into Stage 3: the production implementation must remain in the 3,000–5,000-line planning range unless a scope/architecture ADR explains and approves the deviation.

Issue [#64](https://github.com/nenb/cogs/issues/64) tracks the Stage 3 SSH/SFTP sandbox tool work. PR #76 completed the SSH connection/security foundation. PR #77 completed the SFTP `read`/`write`/`edit` portion. Issue #64 remains open; the remaining work is the SSH-backed `bash`/exec slice, including `/workspace` command execution, stdout/stderr streaming, cancellation, process-group termination attempts, bounded output, exit/signal reporting, Pi update publication, and adversarial coverage.

The production line-count definition for this gate is: git-tracked TypeScript production files under `src/**/*.ts`. Tests do not count. Docs, scripts, deployment harnesses, and development utilities do not count because they are outside `src/`.

Reproducible inventory command from clean `main`:

```sh
git ls-files 'src/**/*.ts' | xargs wc -l
```

Clean-main inventory before the bash/exec implementation:

| Production module | Lines |
|---|---:|
| `src/api/server.ts` | 1,126 |
| `src/launch/config.ts` | 96 |
| `src/launch/lifecycle.ts` | 343 |
| `src/pi/session.ts` | 835 |
| `src/ssh/connection.ts` | 1,243 |
| `src/ssh/file-tools.ts` | 556 |
| **Total** | **4,199** |

A discarded local bash draft showed that a robust implementation needs additional production structure beyond the already-merged SFTP adapter:

- a narrow manager-owned SSH exec channel/port with no raw `ssh2` client or channel exposure to Pi-facing code;
- reconciled terminal handling across `exit`, `close`, `error`, and malformed callback/event behavior;
- bounded cancellation and process-group cleanup attempts with fail-closed readiness behavior when cleanup is not confirmed;
- bounded stdout/stderr sinks, UTF-8 handling, truncation metadata, and serialized Pi `onUpdate` publication;
- adversarial output, callback, cancellation, disconnect, and cleanup tests comparable to the SFTP hardening already merged.

Splitting the remaining work into smaller PRs improves review quality and risk control. It lets reviewers inspect connection-adapter, bash-tool, Pi-publication, and evidence changes in bounded increments. However, smaller PRs do not solve the aggregate line-budget gate: once merged, the production `src/**/*.ts` total still grows by the sum of those slices. The gate therefore needs an explicit architectural decision before the implementation crosses 5,000 production lines.

## Decision

Approve a bounded production line-count exception **only for completing issue #64 bash/exec work**.

Until issue #64 is closed, production TypeScript under `src/**/*.ts` may grow up to **5,750 lines** for the remaining SSH-backed bash/exec implementation and its directly required integration with the existing SSH connection manager and Pi tool-port boundary. If completing issue #64 would cross 5,750 production lines, implementation must pause for another scope/architecture ADR before adding more production code.

This is a bounded next-review trigger, not an unlimited exception. It does not pre-authorize later authentication, proxy, history, export, launch-lifecycle expansion, AWS, release, or other Stage 3 work. After issue #64 is closed, this issue-specific exception is exhausted; later deviations from the 3,000–5,000 planning range need their own ADR unless separately approved.

Retain the current no-guest-daemon SSH/SFTP architecture and modular trust-boundary adapters:

- the SSH connection manager remains the owner of SSH/SFTP/exec channels;
- Pi-facing code receives narrow Cogs tool ports, not raw `ssh2` clients or channels;
- bash/exec is added as another bounded adapter behind that manager-owned boundary;
- fail-closed validation, cleanup, redaction, truncation, and adversarial handling must not be compressed merely to satisfy the planning estimate.

Reject a custom guest helper/service for this decision. A guest helper broadens the protocol, deployment, upgrade, authentication, and trust-boundary surface beyond the current SSH/SFTP adapter design. It would also separately trigger `IMPLEMENTATION.md` §47 and requires its own architecture review before any implementation.

Every PR using this exception must report the measured production `src/**/*.ts` line count using the command above in its PR body or evidence notes.

## Scope boundaries and non-decisions

This ADR does not approve:

- completion or closure of issue #64 by itself;
- any specific `bash` implementation detail not reviewed in code;
- a custom guest daemon, helper, or service;
- fallback from SSH to local tools, host shell, system `ssh`, filesystem access, or direct network access;
- PTY, stdin, agent forwarding, X11 forwarding, SSH agent use, or unrelated SSH features;
- AWS, EKS, production, release, or stronger Linux/KVM isolation claims;
- any detached-process cleanup claim without later implementation evidence that explicitly proves that behavior.

The implementation must preserve the existing Stage 3 authority boundary: insecure-container or local OpenSSH smoke tests are functional-only, while authoritative isolation/security claims require Linux/KVM evidence.

Issue #64 remains open until all of its required work and evidence are complete.

## Consequences

The remaining issue #64 work can proceed, if accepted by the owner, without forcing unsafe compression of SSH exec, cancellation, streaming, redaction, and adversarial-output handling. The guardrail is intentionally narrow: 5,750 production `src/**/*.ts` lines, issue #64 bash/exec only, measured in affected PRs, with another ADR required before crossing that threshold.

## Rejected alternatives

### Compress the bash implementation to stay below 5,000 lines

Rejected. Cleanup, terminal-state, streaming, callback, malformed-event, redaction, and output-bound hardening should not be omitted or compressed merely to satisfy the planning estimate.

### Split issue #64 into smaller PRs as the line-budget remedy

Rejected as a line-budget remedy. Smaller PRs are still preferred for reviewability and risk control, but they do not change the aggregate production size needed to finish the issue #64 SSH bash behavior safely.

### Approve an unbounded Stage 3 line-count increase

Rejected. This ADR is deliberately limited to issue #64 bash/exec work and to 5,750 production `src/**/*.ts` lines. Broader Stage 3 growth needs separate review.

### Introduce a custom guest daemon/helper now

Rejected for this decision. A custom guest component would change the SSH/SFTP architecture, broaden protocol/deployment/trust boundaries, and separately trigger `IMPLEMENTATION.md` §47.
