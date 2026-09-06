# ADR 0308: Retire the paused chain and authorize external-review remediation

- Status: Accepted
- Date: 2026-09-06
- Accepted by: Nick Byrne through the explicit instruction to orchestrate and implement `TEMP-PLAN.md` through one replacement authoritative non-AWS chain, then stop
- Review baseline: `242bbefeae5444118d9e97b46597130b509ca253`

## Context

ADR 0307 froze H `8907eba3191d07573cd84573cb0b2adddff17bd6`, producer `34028384783`, and direct-child G `242bbefeae5444118d9e97b46597130b509ca253`. G's ordinary CI passed. Linux/root run `34033114319`, attempt 1, had every completed job passing while `network-runtime` remained in progress when last observed. No publisher was dispatched.

An external review of older revision `d14cf4f785ea13974fabfc01a72c7c39ba10db86` identified application security and evidence-quality concerns. Five independent read-only triage reports assessed all thirteen findings against G using bounded local reproductions and source/design tracing. The reports distinguish source-confirmed gaps, architectural limitations, and real-runtime experiments still required. A clean local baseline ran 1,336 tests: 1,329 passed, seven were explicitly skipped, and none failed. Green baseline tests do not close the findings.

The review and triage establish a common error pattern: an observation was sometimes treated as a stronger fact than it proves. Examples include a timeout as retirement, fsync of a valid prefix as complete persistence, numeric version as secret incarnation, missing traffic as firewall enforcement, and queue retention as durable audit.

## Current-head disposition

| # | Disposition at the reviewed baseline | Required closure |
|---:|---|---|
| 1 | Confirmed: an accepted multi-star path can block synchronous JavaScript matching, including matching-language inputs | Closed bounded matcher and overlap logic; production Envoy differential tests |
| 2 | Confirmed: numeric OpenBao version permits delete/recreate ABA and hydration discards data identity | Exact pinned-data provenance, qualified incarnation tuple, immutable baseline, terminal invalidation, and proven retirement |
| 3 | Confirmed: the KVM relay fabricates valid proxy authentication for an anonymous caller and does not prove source/interface binding | Forward the existing guest session capability and enforce the exact host tuple/interface |
| 4 | Confirmed: several bypass denials are non-causal because destinations are not demonstrably live | Same-tuple live controls, trusted observations, and isolated enforcement-removal mutations |
| 5 | Confirmed: dependency shutdown failures and deadlines can produce false success or discard observation of live work | Sticky failed observation distinct from actual retirement; dependency-safe release and replacement exclusion |
| 6 | Confirmed: a native Pi persistence exception can leave memory ahead of JSONL, reopen admission, and later fsync a shorter valid prefix | Synchronous writer-failure latch, exact durable frontier, and one all-outcome settlement gate |
| 7 | Confirmed: response code `0` and an undrained 64-record queue poison egress; ordinary OTLP failure is already partly separated | No-response category, continuous owned consumption, bounded process backpressure, and optional telemetry loss accounting |
| 8 | Confirmed: accepted tool content and paged history are silently clipped while retaining contradictory completion metadata/cursors | Truthful tool admission plus complete redacted transport fragmentation of permitted bytes |
| 9 | Confirmed: request paths are not checked against `reject-ambiguous`; actual upstream impact depends on downstream decoding | Original/forwarded path contract, hostile corpus, and real-client compatibility or explicit narrowing |
| 10 | Confirmed: authenticated session reconstruction drops both validated checkpoint fields | Forward both fields and test the authenticated enabled paths |
| 11 | Confirmed: exact edit uses JavaScript replacement-string interpretation | Literal unique-index splicing and replacement-token tests |
| 12 | Confirmed design contradiction: native retry and compaction are explicitly disabled | Restore bounded native behavior after persistence closure, or record a later explicit design supersession |
| 13 | Confirmed architectural limitation and documentation omission | State approved-upstream reflection/storage trust and demonstrate it with synthetic credentials |

Finding 10 is not already fixed: direct construction preserves the fields, but `createAuthenticatedCogsPiSession` drops them.

## OpenBao field qualification

A local diagnostic used exact image `quay.io/openbao/openbao:2.6.1@sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0`, private tmpfs, loopback random port, and synthetic values. It observed:

- metadata exposes exact `created_time`, `current_version`, and per-version `created_time`;
- pinned `?version=N` data reports the same exact per-version `created_time` and numeric version;
- metadata deletion makes old versions unavailable;
- recreation resets to numeric version 1 but changes exact creation timestamps;
- twenty rapid recreations repeated neither exact nor millisecond-collapsed tuples in that finite sample.

The successful owned fixture was removed with `docker rm -fv` and exact-name absence was verified. An earlier stopped setup diagnostic created image-declared anonymous volumes and removed its container without retaining exact volume identities; it is local diagnostic uncertainty and grants no cleanup or qualification claim.

Accept the structured incarnation tuple:

```text
schema, trusted authority binding, mount, scoped handle,
current numeric version, key created_time, current-version created_time
```

Compare timestamps as exact full-precision strings. Read metadata M0, fetch explicit version N, require data version/time equality, read metadata M1, and require M0=M1 before use. Deduplicate hydration by handle and derive the watcher baseline from the hydrated manifest.

This detects API-mediated recreation under trusted-clock/storage, non-repeating creation identity, stable authority, and consistent-read assumptions. Snapshot rollback, identical restore, backend substitution, malicious metadata, and a transient delete/undelete wholly between observations are outside this tuple's guarantee. Expanding that threat scope requires an external non-reused epoch and a new decision; hashing more fields is not a substitute.

Polling detection is bounded as `P + 2R + J`: poll wait P, up to two aggregate observation bounds R in the worst phase, and declared scheduler allowance J. Retirement adds independently enforced D. No polling path is called immediate, and replacement-ready has its own external provisioning bound.

## Decision

Permanently retire ADR 0307's H, G, diagnostic `34023790672`, producer `34028384783`, and artifact `9988125363` from future authorization. Preserve them as historical facts. Supersede the unused publisher permission. Do not dispatch a publisher, static observation, preflight, or qualification for that tuple.

Authorize one coordinated remediation wave with one lead editing path. Parallel agents may reproduce, design, test, and review, but may not independently merge overlapping interface changes.

### Shared contracts

1. **Terminal admission epochs.** Revocation and persistence invalidation close admission synchronously and irreversibly for one generation. Asynchronous authorization rechecks after WAL append and before allow.
2. **Owned close and retirement.** One absolute deadline bounds caller observation only. Owners record acquisition/work before effects, retain actual work and exact resources, independently initiate safe termination, and release dependencies only after their users retire. Timeout or cancellation leaves sticky uncertainty and replacement exclusion.
3. **Hydrated identity manifest.** Egress uses one M0→pinned-data→M1 value and identity per distinct handle. No xDS or generic secret framework is added.
4. **Native durable frontier.** An instance-local fence on the pinned Pi 0.84.2 `SessionManager` observes synchronous `_persist` failure before Pi can normalize it, guards public mutators, and commits exact append history only after full validation and fsync. Native JSONL remains unchanged. Pi live context need not equal append history after retry/compaction.
5. **Bounded completion handoff.** Durable credential-use intent remains fail-closed. Completion observation and ordinary OTLP delivery remain separately bounded and loss-accounted; collector outage does not terminate valid egress.
6. **Causal network cases.** A small shared topology/case description binds source/interface/destination/protocol/nonce to live fixtures and trusted observations. It is test infrastructure, not runtime policy authority.

### Narrow implementation choices

- Implement exact, prefix, and positive-length segment-glob matching with bounded iterative logic. Generate Envoy RE2 only from the same validated grammar and never execute it with JavaScript regex.
- Begin with visible canonical ASCII paths and reject percent, backslash, repeated slash, dot-only segments, and path parameters. Real Git/npm/pip tests decide explicit supported subsets. Scoped npm metadata is unsupported unless a separately proved single-interpretation encoding is added.
- Reuse the existing per-session proxy capability. Guest possession is already accepted; source/interface binding limits copied use. Do not create a second relay token lifecycle.
- Run firewall-removal tests only inside verified disposable namespaces/VMs with no ordinary uplink and synthetic credentials. No host-firewall fallback is permitted.
- Keep lifecycle `failed` terminal when the original shutdown fails, even if later recovery proves retirement. Emit no shutdown-success telemetry for that attempt.
- Where process-tree or remote-work retirement cannot be proved, preserve custody and deny replacement/reuse. Leader exit, listener refusal, socket closure, or worker PID absence alone is insufficient.
- Use the pinned instance-local Pi persistence seam; no SDK fork, alternate agent loop, or second transcript is authorized. Upgrade requires re-audit of the seam.
- Add a transport-only fragment endpoint/version for deterministic redacted entry bytes. Use bounded session/startup-scoped signed cursor state; no raw secret, raw history digest, or alternate transcript. Existing raw export remains explicit, authenticated, sensitive, and unchanged. Secrets intentionally redacted are permanently absent from this projection.
- Admit complete tool results within explicit JSON/node/depth/byte limits or return a fixed error. Never silently clip and retain success-shaped source metadata.
- Accept completion code exactly `0` or `100..599`; codes `1..99` remain invalid. Code 0 is categorized as no response headers, never HTTP success.
- Land literal edit and checkpoint forwarding as narrow fixes. Restore bounded native retry/compaction only after the durable fence covers their caught errors and cancellation paths.
- State explicitly that an approved upstream can reflect, store, log, or later return an injected credential. No response DLP or secret-erasure claim is added.

### Non-goals

This work does not add a general policy engine, workflow framework, process scheduler, database, transcript format, xDS control plane, second capability protocol, response DLP system, durable completion rotation system, cloud client, provider action, or automatic prompt replay.

## Measured accounting and bounded allocation

At the baseline, the retained Stage 2 counter reports:

```text
physical retained set:              90,354
conservative no-deletion total:     94,002
correction deploy/retained/workflow: 21,948 / 11,862 / 4,838
correction global:                  38,648
tracked files:                       1,420
source-inventory included entries:   1,417
source-inventory included bytes:     18,763,891
```

The 94,100 limit applies to enumerated Stage 2 deployment, retained, workflow, and control members, not every tracked source file. Every tracked change nevertheless changes complete H.

Authorize these one-time gross no-deletion ceilings from baseline `242bbefe...`:

| Workstream | Gross ceiling |
|---|---:|
| route/path/reflection | 3,000 lines |
| hydration/revocation | 1,700 lines |
| relay/causal network evidence | 2,600 lines |
| lifecycle/native persistence | 4,800 lines |
| completion/history/small Pi fixes | 2,700 lines |
| integration/accounting/evidence wiring | 1,200 lines |
| **total** | **16,000 lines** |

Replacement lines, moves, and formatting count as additions. Deletions create no credit. Accounting is the baseline-to-endpoint added-line diff, not cumulative intermediate-commit churn. Git rename/copy detection is disabled so a moved destination is charged as an addition. These are ceilings, not targets, and do not permit removing hostile tests to fit.

Use whole-file ownership, not unverifiable hunk attribution. The exact allocation is `config/external-review-remediation-budget-v1.json`; an unknown changed path fails until a reviewed allocation update assigns it. Nominal exact files are matched exactly, not by lookalike prefixes. Allocated ignored inputs, unsupported binary diffs, partial v5 packages, and unsafe untracked file identities fail closed.

Raise the intersecting Stage 2 correction highs once:

```text
deployment       22,000 -> 22,300
retained         12,100 -> 13,100
workflow          5,000 ->  5,500
global           38,700 -> 40,500
hard stop         94,100 -> 95,900
```

Keep the 90,000 preference advisory and the strict combined mutable-owner limit below 2,000. Explicitly add the future v5 package to exact control-data inventory and charge its members; suffix omission creates no free capacity.

Retain the tracked-source ceiling of 1,460. The allocation manifest permits at most 40 new files total from the 1,420-file baseline, including all 13 exact future v5 members and the later H/G/Q decisions. Its named baseline-absent paths fit each owner's new-file high; unused slots are unassigned contingency and remain unusable until a reviewed exact-path allocation update. This deliberately replaces the broader review estimate of 40 remediation files plus 20 later files. Prefer extending existing tests.

Raise only the complete source aggregate bound from 18 MiB to 21 MiB (`22,020,096` bytes). The measured baseline is 18,763,891 bytes, leaving 3,256,205 bytes. The allocation forecasts 2,570,000 gross bytes: route 350,000; revocation 220,000; relay 400,000; lifecycle 750,000; completion 500,000; integration/final custody 350,000. This leaves 686,205 bytes of contingency. The baseline serialized inventory was 219,842 bytes; the first staged architecture set measured 220,177 bytes. Forty entries at the manifest's 104-byte longest planned path envelope remain within the unchanged 256 KiB consumer bound. Keep 4 MiB/file and all other readiness artifact bounds unchanged.

The future v5 state is exactly absent before Q or exactly complete with its ten contracts and three package members; partial, extra, or ignored state fails. Add its lines to the existing legacy deploy/global gross accounting when present.

Add the exact allocation, gross additions, new-file use, byte forecasts, and v5 state to the machine-readable existing accounting report. Exceeding a workstream, Stage 2 slice, source cardinality, source byte, mutable-owner, or hard bound stops implementation. It does not automatically authorize another increase.

## Validation

Before replacement H:

1. Preserve a failing regression for every confirmed defect.
2. Pass focused unit and mutation tests continuously.
3. Pass format, typecheck, schema, preset, descriptor, image, lock, license, audit, source-inventory, and deterministic readiness checks.
4. Run real pinned Envoy and OpenBao fixtures with synthetic credentials.
5. Run real Git clone/fetch, unscoped npm registry install, and pip simple-index install through the production path contract; document unsupported encoded capabilities.
6. Run sustained completion traffic and prolonged OTLP outage while durable WAL failure still denies.
7. Run persistence faults across prompt, steer, follow-up, abort, model/tool error, retry, compaction, navigation, shutdown, and export.
8. Run isolated dual-stack TCP/UDP/real-DoH mutation cases and applicable KVM source/interface cases. Raw UDP is not labelled QUIC without a real QUIC protocol test.
9. Pass Linux/root process, ownership, late-factory, cleanup, and recovery tests.
10. Obtain independent route, revocation, relay/network, lifecycle/persistence, completion/history, and holistic reviews with no blockers.
11. Regenerate readiness/source evidence only after the final tracked change and prove deterministic rerender.

A test exception, no route/listener/client, failed fixture, stale artifact, timeout, cleanup uncertainty, or diagnostic result cannot become a pass.

## Deferred authoritative chain

No remediation commit, ordinary CI result, fixture run, or reusable diagnostic has authoritative qualification status. Only after the complete integrated revision and final reviews pass may a later record:

1. freeze replacement H and pass protected CI/Linux-root;
2. run and audit one exact-H no-mint full/readiness diagnostic;
3. run and audit one sole first-created attempt-one producer;
4. establish protected sole-parent G with authority cleared;
5. run and audit one publisher and one no-KVM static observation;
6. commit exact observed v5 bytes as sole-parent Q and pass protected checks;
7. verify and set exact H/G/Q bindings;
8. run and audit one mixed preflight;
9. run and audit one seven-runner formal qualification;
10. freeze the final non-AWS evidence and stop.

H proves executable source identity. G independently binds H to control observations. Publisher proves immutable external custody and signature/readback. Static observation proves the exact no-build control package. Q commits only the independently observed package as authenticated data, never executable authority. Preflight proves mixed H/G/Q preparation and cleanup. Formal qualification proves seven independent lifecycle observations. Provenance complements and cannot replace hostile behavior tests.

## Consequences

All failed, canceled, retried, malformed, artifactless, stale, cleanup-uncertain, diagnostic, and retired runs remain non-authorizing. No H/G/Q identity is assigned by this decision.

This ADR authorizes local/static remediation, ordinary protected CI, explicitly non-authorizing diagnostics after implementation convergence, and the later non-AWS chain above. It grants no AWS credential access, AWS API, provider/OpenTofu execution, SSM, inventory, deployment, production campaign, Issue #42 closure, Stage 4 authority, or release claim. Work stops after the final non-AWS evidence freeze for separate authorization.
