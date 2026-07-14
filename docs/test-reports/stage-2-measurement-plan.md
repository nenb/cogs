# Stage 2 bounded measurement harness plan

Status: harness design for issue #42; no AWS campaign has been run for this plan. Issue #42 must remain open after this PR unless a later, authorized campaign produces evidence for every acceptance criterion.

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

Default sample count is seven and is bounded to 5–9. Every timed sample must be at least 25 ms or the remote harness and validator fail closed.

| Measurement | Workload | Interpretation |
|---|---|---|
| Kata cold boot p50/p95 | `ctr --runtime io.containerd.kata.v2 --runtime-config-path "$config" --rootfs --read-only` boots a fixed BusyBox rootfs and prints UID/kernel | Authoritative repeated Kata/containerd startup on the selected host |
| Warm CPU workload | Sixteen SHA-256 passes over a fixed 16 MiB payload on host BusyBox and inside a persistent Kata task via `ctr tasks exec` | Relative warm in-guest CPU micro-workload ratio, excluding cold boot |
| Warm filesystem workload | Four passes reading 1024 deterministic small files on host and inside a persistent Kata task; guest commands use explicit `/bin/busybox find`, `/bin/busybox xargs`, and `/bin/busybox cat` | Relative warm in-guest read-heavy small-file ratio, excluding cold boot |
| Host Git baseline | Repeated `git grep` on a synthetic 512-file local repository | Host instance baseline only; representative sandbox Git acceptance remains unmet |
| Host package-build baseline | `make clean all` for a deterministic C program | Host compiler/build baseline only; representative sandbox package/build acceptance remains unmet |
| Idle memory | Start one sleeping Kata task, identify exactly one newly created `qemu-system-x86_64` PID, and read `/proc/$pid/status` RSS | Authoritative QEMU RSS signal or fail closed |
| Density | `min(memory bound after 1024 MiB host reserve using max(QEMU RSS, configured guest memory), CPU bound using host vCPUs/configured guest vCPUs)` | Conservative bound only; not a scheduler recommendation |

## Fail-closed and redaction requirements

- The controller refuses to send the SSM script unless the tree is clean and the checked-out HEAD exactly matches the planned source revision.
- Any failed stage exits non-zero, emits a bounded stage marker, and the campaign orchestrator destroys before debugging.
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
