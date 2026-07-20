# ADR 0036: Authorize issue #71 integrated Linux/KVM exit scenario

- Status: Accepted
- Date: 2026-07-20
- Decision owner: Nick Byrne
- Acceptance: Accepted by delegated project lead under Nick Byrne's latest explicit delegation to continue autonomously and make project decisions without waiting.

## Context

Issue #71 is the Stage 3 S3-09 exit gate from `IMPLEMENTATION.md` §§28-29. It requires an authoritative Linux/KVM end-to-end scenario: start a clean KVM VM and trusted services; start Cogs with test identity, project, skills, model API key, and integration preset; submit a prompt through HTTP; have Pi use SSH/SFTP tools to read and edit a repository and run tests; perform allowed and denied guest egress; prove live events plus paged history after replay eviction; map a Git commit/checkpoint to the correct Pi entry; open raw export with pinned Pi tooling; shut down; prove cleanup; and run the full applicable real egress conformance suite from guest root.

The accepted issue #70 launcher and follow-up hardening provide most underlying mechanisms, but the literal #71 acceptance criteria are not satisfied by aggregation alone. Separate successful launcher smoke, real-runtime KVM egress, and unit evidence prove components and prerequisites, not one integrated Pi-driven KVM scenario. In particular, current `main` has these integrated-scenario gaps:

- launcher smoke drives only the fixed deterministic bash tool path, not a multi-tool repository read/edit/test flow;
- launcher smoke does not make the guest perform both allowed credentialed HTTP and denied HTTP through the same Pi/tool/session path;
- launcher smoke calls history but does not force replay eviction and then rebuild via paged durable history;
- launcher trusted composition currently sets Git notes on but checkpointing off, so the exit scenario does not produce a checkpoint-backed Git mapping;
- launcher sensitive export cleanup exists, but #71 needs the same scenario export opened with pinned local Pi tooling before exact deletion; and
- final evidence must bind startup, run, egress, history, checkpoint, export, shutdown, destroy, and absence proof to one authoritative Linux/KVM scenario at one source revision.

Current pre-implementation measured baseline on `origin/main` `0907fd1f0d0dcd927f51fd764d06d799659ce6f2`:

```text
dev/launcher/**/*.ts: 12,219 total
src/**/*.ts:          22,479 total
```

ADR 0035 leaves only 181 non-test launcher TypeScript lines below its hard cap of 12,400, while a readable fixed integrated scenario needs more than that. Compressing scenario orchestration, checkpoint/replay wiring, and evidence validation into the remaining margin would weaken reviewability and repeat the security-compression failure mode rejected by ADR 0029, ADR 0032, and ADR 0034.

## Decision

Authorize only the fixed issue #71 integrated authoritative Linux/KVM S3-09 scenario work, and raise only the development-launcher numeric caps needed for that issue #71 scenario.

This ADR supersedes only ADR 0035's launcher numeric caps for the S3-09 integrated scenario. ADR 0035 remains the issue #70 operations cap outside #71. This ADR does not alter ADR 0034's production `src/**/*.ts` caps and does not authorize unrelated launcher refactoring, cloud work, production daemon work, release work, or new dependencies.

The new non-test launcher TypeScript caps for #71 changes under `dev/launcher/**/*.ts` are:

```text
preferred: 13,100 lines
hard cap:  13,400 lines
```

Production `src/**/*.ts` caps remain unchanged:

```text
preferred: 22,800 lines
hard cap:  23,400 lines
```

Implementation should target zero production `src` expansion and no new dependency. Any production `src` change must be separately justified in the PR and remain under ADR 0034 caps.

## Measured launcher line budget

The cap is set before implementation from measured function/slice estimates, not after-the-fact to excuse a completed diff. The current 12,219-line launcher baseline leaves this planned budget:

| Area | Estimated launcher lines | Notes |
| --- | ---: | --- |
| Fixed CLI/operation surface | 40-70 | Add one exact `s3-09` operation/mode and argument rejection. No arbitrary scenario selection or command input. |
| Integrated operation orchestration | 150-220 | Create/start/run/events/history/export/shutdown/destroy sequencing, metadata-only result shape, and cleanup-on-failure. |
| Deterministic multi-tool stream | 140-210 | Fixed Pi stream for read, edit/write, bash test, allowed egress, denied egress, and final answer. No prompt scripting. |
| Scenario mode wiring | 90-150 | Carry fixed scenario mode into trusted composition, enable checkpoint only for S3-09, and bound replay capacity if needed. |
| Guest workspace and probe helpers | 110-170 | Fixed Git fixture preparation and fixed allowed/denied guest HTTP probes through existing SSH/SFTP and Envoy paths. |
| Export opening and report helpers | 70-120 | Open same-run raw export with pinned repo-local Pi tooling, validate metadata/report shape, and retain exact deletion proof. |
| Contingency for readable fail-closed validation | 81-241 | Review-driven hardening, hostile-shape checks, and cleanup uncertainty handling without compression. |
| **Projected addition** | **681-1,181** | Preferred cap allows 881 lines over baseline; hard cap allows 1,181. Implementations above preferred must justify the overage; above hard must stop. |

The preferred cap intentionally supports the midpoint of the measured launcher-only estimate without moving orchestration into production `src`. The hard cap supports the high estimate and review-driven safety fixes without compressing security-critical code. Exceeding the hard cap requires stopping for new evidence and a superseding ADR.

## Authorized scenario behavior

The authorized S3-09 scenario is exact and fixed:

1. Run only on `linux-kvm`, the sole authoritative local security profile. Missing KVM/QMP/root-network prerequisites fail closed with no fallback.
2. Use the existing development launcher and trusted composition. The launcher remains development tooling only.
3. Require externally provisioned `/run/cogs/egress` and `/run/cogs/ssh` Linux tmpfs roots: canonical, non-symlink, current uid/gid, mode `0700`, empty at required boundaries. The launcher must not create or mount them through hidden `sudo`.
4. Submit a fixed prompt through the authenticated HTTP API.
5. Drive Pi through fixed deterministic model output so the normal tool ports perform repository read, edit/write, and a fixed test command over existing SSH/SFTP tools in the guest workspace.
6. Perform one allowed credentialed HTTP request from the guest through the existing integration preset, Envoy, OpenBao, WAL, and completion path. The guest must not see the real credential, proxy capability must be stripped upstream, and WAL intent must precede credential use.
7. Perform one disallowed guest HTTP request and prove it fails closed without reaching upstream.
8. Stream live events, force replay eviction through a bounded fixed replay-capacity path, then rebuild the scenario through authenticated paged history backed by durable native Pi JSONL.
9. Enable Git checkpointing only for the fixed scenario and prove the resulting checkpoint/Git mapping is tied to the correct Pi entry/turn as an untrusted observation.
10. Request raw export, open the same export with pinned repo-local Pi tooling/library, validate expected shape and forbidden-value absence, then remove the sensitive local export with retained-handle deletion, parent fsync, and absence proof. The sensitive export must never be uploaded.
11. Shut down through the authenticated API, stop the exact worker child by durable PID identity, destroy exact owned sandbox/profile state, and prove no launcher resources remain. Cleanup uncertainty is failure and preserves recovery state.
12. Reuse the existing KVM qualification and full applicable real egress conformance suite in the same PR/head evidence flow. Conformance evidence remains a companion requirement and does not replace the integrated Pi-driven scenario.

## Required PR slicing

Implementation must be split into two PRs unless a later review explicitly accepts a smaller plan:

1. **Scenario capability PR**: add the fixed S3-09 launcher/scenario capability and tests. It must report `dev/launcher/**/*.ts` and `src/**/*.ts` line counts and stop below the hard caps. It must not include accepted evidence claims from an unrun scenario.
2. **Evidence/workflow/docs PR**: add the evidence harness/workflow wiring and redacted report documentation after the scenario capability exists. This slice should add no launcher or production `src` code unless separately justified and measured.

Do not mix issue #164 reliability/refactor work into either #71 slice.

## Provider/API-key boundary

This ADR does not authorize external real-provider model calls, provider API-key use, provider network traffic, or execution of `scripts/pi-real-provider-integration.ts`.

Existing local launcher composition may prove the narrower boundary that an OpenBao-resolved model API key is supplied to Pi as runtime-only in-memory auth and is not persisted or leaked. That is not evidence of a real external provider call. Any real-provider S3-09 evidence remains blocked until explicit authorization and runtime key provisioning are provided. If authorization is not provided, #71 evidence must state the provider-call subcriterion as blocked/not executed rather than overclaiming it.

## Reaffirmed security and applicability boundaries

All earlier Stage 3 security boundaries remain binding:

- no profile fallback, local-tool fallback, runc fallback, open-egress fallback, anonymous-auth fallback, symlink/bind fallback, hidden sudo mount, repo-path SSH fallback, software-emulated KVM claim, or native macOS full-egress fallback;
- no arbitrary command strings, shell fragments, generic child argv, arbitrary executable paths, user-selected images, user-selected scenarios, arbitrary project paths, or runtime scenario scripting;
- no new dependencies without a new reviewed decision;
- credentials, OpenBao tokens, model keys, integration credentials, proxy capabilities, startup nonces, private keys, prompts, model output, source content, complete commands, tool output, HTTP query/body, account IDs, raw provider IDs, raw provenance digests, private paths, and inode values must not enter reports, telemetry, status, manifests, ordinary logs, or uploaded artifacts;
- telemetry and evidence remain metadata-only;
- real credentials, trusted proxy state, CA private keys, OpenBao root/scoped tokens, and API tokens remain outside the guest and callback-scoped where applicable;
- guest/host identity must remain explicit: active KVM, root guest, distinct boot identity, host-owned TAP enforcement, guest firewall untrusted, no default route, and fixed proxy reachability only;
- Envoy remains the selected egress proxy, not the isolation boundary;
- Pi-owned runtime cleanup remains the only authority for Pi host runtime files; the launcher consumes only success/failure and must not broadly delete Pi runtime trees;
- shutdown/export/destroy cleanup uncertainty must fail closed and preserve recovery controls; and
- evidence is authoritative-local Stage 3 evidence only, not AWS, cloud, EKS, deployment, release, compliance, production-authentication, production-readiness, general availability, or broad cloud-isolation evidence.

## Stop gates

Implementation must pause before proceeding if any of the following occur:

- non-test `dev/launcher/**/*.ts` would exceed **13,400** lines;
- `src/**/*.ts` would exceed ADR 0034's **23,400** hard cap;
- the scenario requires a new production dependency or broad production `src` expansion;
- arbitrary commands, prompt-programming, generic scenario selection, user-selected paths/images, or unbounded fixture behavior is proposed;
- checkpoint/replay/export evidence cannot be tied to the same integrated Pi entry/session without leaking sensitive data;
- any cleanup uncertainty would report success or delete unknown/replaced content;
- either `/run/cogs/egress` or `/run/cogs/ssh` prerequisite is loosened;
- KVM falls back to TCG/container/software emulation or the profile changes from `linux-kvm`;
- telemetry/evidence would include forbidden content rather than metadata;
- a manual diagnostic push loop, force-push/rerun cycle, or manual workflow dispatch is proposed for acceptance evidence instead of one clean PR-head automatic evidence flow;
- external provider calls or runtime provider keys are requested without explicit authorization; or
- AWS, cloud, deploy, release, production daemon, scheduler, production authentication service, compliance, or production-readiness scope is requested.

## Consequences

Issue #71 can proceed with a readable integrated Linux/KVM exit scenario rather than overclaiming aggregated component evidence. The launcher cap increase is narrow, measured, and pre-implementation. It exists only to implement and evidence the fixed S3-09 scenario safely.

Future #71 PRs must report measured line counts, keep evidence metadata-only, preserve all no-fallback and cleanup boundaries, and stop for a new ADR if the hard caps or scope boundaries are insufficient.
