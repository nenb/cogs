# Stage 2 bounded measurement harness plan

Status: harness design and authorized campaign outcomes for issue #42. Four post-merge Stage 2 measurement campaigns were attempted after checked plans and failed closed; no pass evidence was produced, destroy completed immediately, independent inventory returned zero after each failure, and issue #42 remains open.

## Scope reconciliation

Issue #42 asks for cold/readiness, overhead, workload, density, duration, cost, report, destroy, inventory, and redaction evidence. `COGS.md`, `DESIGN.md`, and `IMPLEMENTATION.md` constrain Stage 2 to a short-lived single EC2 host, not EKS, not production, and not a general isolation or availability claim.

The harness therefore measures only the authoritative Stage 2 surface:

- one CPU-only `c8i-flex.large` in `us-east-1` through the checked OpenTofu flow;
- active host KVM and a root Kata 3.32.0 QEMU guest with a distinct kernel;
- repeated Kata/containerd cold starts inside the single host;
- warm deterministic synthetic CPU/filesystem workloads via `ctr tasks exec` inside one verified persistent Kata task, compared with host execution of the same BusyBox workload;
- deterministic synthetic host Git and package-build baselines only; these do **not** satisfy representative sandbox Git/build/package workload acceptance;
- one apply-to-running and apply-to-SSM-online readiness observation from the checked apply path; this is not SSH-ready timing;
- deterministic QEMU RSS measurement for a newly created, unique idle Kata QEMU process;
- configured guest memory/vCPU extraction from the checked Kata config and a conservative density bound using the greater of measured QEMU RSS and configured guest memory; and
- a fail-closed campaign orchestrator that destroys, independently proves zero inventory, and only then finalizes publishable evidence on success, failure, validation failure, or interrupt.

The harness does **not** measure repeated EC2 launch p50/p95 or SSH-ready timing. Repeated EC2 launch percentiles would require multiple launches or stop/start cycles, and SSH-ready timing would require enabling SSH. Both exceed the approved Stage 2 one-instance SSM-only profile. It also does not measure EKS scheduled-to-ready timing or representative sandbox Git/build/package workloads. These remain unmet for issue #42 unless separately authorized and measured.

## Deterministic workloads

Default sample count is seven and is bounded to 7–9. Every accepted timed sample must still run the fixed workload and be at least 25 ms or the remote harness and validator fail closed.

| Measurement | Workload | Interpretation |
|---|---|---|
| Kata cold boot p50/p95 | `ctr --runtime io.containerd.kata.v2 --runtime-config-path "$config" --rootfs --read-only` boots a fixed BusyBox rootfs and prints UID/kernel | Authoritative repeated Kata/containerd startup on the selected host |
| Warm CPU workload | Sixteen SHA-256 passes over a fixed 16 MiB payload on host BusyBox and inside a persistent Kata task via `ctr tasks exec` | Relative warm in-guest CPU micro-workload ratio, excluding cold boot |
| Warm filesystem workload | Sixteen passes reading 1024 deterministic small files on host and inside a persistent Kata task; guest commands use explicit `/bin/busybox find`, `/bin/busybox xargs`, and `/bin/busybox cat` | Relative warm in-guest read-heavy small-file ratio, excluding cold boot |
| Host Git baseline | Repeated `git grep` on a synthetic 512-file local repository | Host instance baseline only; representative sandbox Git acceptance remains unmet |
| Host package-build baseline | `make clean all` for a deterministic C program | Host compiler/build baseline only; representative sandbox package/build acceptance remains unmet |
| Idle memory | Start one sleeping Kata task, identify exactly one newly created `qemu-system-x86_64` PID, and read `/proc/$pid/status` RSS | Authoritative QEMU RSS signal or fail closed |
| Density | `min(memory bound after 1024 MiB host reserve using max(QEMU RSS, configured guest memory), CPU bound using host vCPUs/configured guest vCPUs)` | Conservative bound only; not a scheduler recommendation |

## Fail-closed and redaction requirements

- The controller refuses to send the SSM script unless the tree is clean and the checked-out HEAD exactly matches the planned source revision.
- Any failed stage exits non-zero, emits bounded non-secret stage/sample/command progress and failure markers, and the campaign orchestrator destroys before debugging.
- Per-command and per-sample timeouts bound package setup, downloads, QMP checks, QEMU probe socket/exit waits, Kata cold boots, warm host/Kata samples, host baseline samples, and idle observation while preserving identical fixed work for host/Kata ratio pairs.
- Configurable sample/timeout/poll/kill-after values are validated against strict numeric or bounded-duration formats before use, and the controller enforces the numeric hierarchy `per-command < remote < SSM < poll < orchestrator`.
- The remote script has a lower end-to-end deadline, runs bounded commands in their own process groups, records the active process group for the watchdog, and the SSM command/poll loop and orchestrator validation wrapper have corresponding bounds.
- Stale evidence/report/remote-result files are removed before a run and again during failed, timed-out, interrupted, or validation-failed cleanup so timeout/TERM/KILL paths cannot publish evidence.
- Kata stderr diagnostics are written and emitted through a true aggregate 8 KiB cap, including diagnostic headers, and sanitized to printable characters.
- Evidence schemas reject unexpected fields and bounded report size.
- The validator recomputes min/p50/p95/max, warm workload ratios, memory/density bounds, timing ordering, sample length, cleanup/zero-inventory finalization, and the `< USD 0.50` four-hour cost bound from raw evidence.
- Machine and human reports must not include credentials, prompts, source, account IDs, instance/network IDs, public IPs, SSM command IDs, budget email, UUIDs, email addresses, or IP addresses.
- Existing OpenTofu plan checks, budget alerts, independent TTL, SSM-only access, and zero-resource inventory remain mandatory.

## Output artifacts

A future authorized run writes ignored local artifacts:

- `.state/stage2-measurement-evidence.json` — schema-validated machine evidence;
- `.state/stage2-measurement-report.md` — human rendering derived from final machine evidence only after destroy and zero inventory;
- `.state/measurement-failure.json` and `.state/measurement-command-id.txt` for local operator diagnostics only; and
- `.state/final-zero-resource-inventory.json` after destroy.

Release or ADR documents may quote redacted aggregate values from these artifacts, but must not commit raw ignored state.

## First authorized campaign outcome

After PR #53 merged, one authorized bounded measurement campaign was run on the merged revision. The checked plan remained inside the one-host `c8i-flex.large`, CPU-only, SSM-only, no-EKS/no-NAT/no-load-balancer/no-EIP/no-EFS boundary with expected cost below USD 0.50. The campaign failed during `warm-workload-samples` because local Kata/containerd task teardown attempted to remove a task/container before containerd had observed task exit. The orchestrator treated this as a failed measurement, produced no validated measurement evidence or human report, destroyed all campaign resources, and independent inventory showed total zero. A second read-only inventory also showed total zero.

After PR #54 merged, exactly one further authorized bounded measurement campaign was run from the merge revision with the same one-host, CPU-only, SSM-only, budgeted and TTL-bound scope. It again failed during `warm-workload-samples` with the same non-stopped Kata/containerd task/container removal symptom. The orchestrator destroyed all campaign resources immediately; orchestrator and independent read-only inventories both showed total zero. This second failed run confirmed the local teardown fix was insufficient and records no measurement pass evidence.

After PR #55 merged, exactly one further authorized bounded measurement campaign was run from the merge revision with the same one-host, CPU-only, SSM-only, budgeted and TTL-bound scope. It failed closed at the 45-minute outer SSM command timeout before producing measurement evidence or a human report. The orchestrator destroyed all 16 campaign resources; orchestrator and independent read-only inventories both showed total zero. The bounded cost estimate was approximately USD 0.075. This third failed run records a harness timeout/diagnosability and cost-control problem only; it is not pass evidence.

After PR #56 merged, exactly one further authorized bounded measurement campaign was run from the merge revision with the same one-host, CPU-only, SSM-only, budgeted and TTL-bound scope. It failed closed during warm workload teardown after completing the seventh warm host/Kata CPU/filesystem sample pair. The new progress diagnostics localized the failure to the warm task stop path and exposed two local shell/lifecycle defects: failure-status clobbering during best-effort cleanup and treating a non-zero `ctr tasks wait` status as authoritative failure even when independently observed task state should be the authority. The orchestrator destroyed all 16 campaign resources; orchestrator and independent read-only inventories both showed total zero. The bounded cost estimate was approximately USD 0.0084. This fourth failed run records local harness teardown defects only; it is not pass evidence.

These failed runs record local harness/teardown lifecycle bugs only; they do not provide measurement pass evidence and do not close any issue #42 acceptance criteria.

## Source-grounded teardown basis

Containerd `v2.2.1` source inspection found that `ctr tasks ls` prints task status from `task.Status.String()` and the task status enum is `UNKNOWN=0`, `CREATED=1`, `RUNNING=2`, `STOPPED=3`, `PAUSED=4`, `PAUSING=5`. The `ctr tasks delete` command supports aliases `del/remove/rm` and an optional `--force`, but Stage 2 teardown does not rely on force deletion. The teardown must independently observe `STOPPED`/`3` or task absence after `ctr tasks wait`; wait completion alone is not treated as sufficient proof that containerd will accept `tasks rm`.
