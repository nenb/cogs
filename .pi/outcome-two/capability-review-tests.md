# Outcome 2 capability tests — hostile review

**Reviewed head:** `9c86bc5` (`review/cap-tests`)  
**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`  
**Scope:** accepted ADR 0087, `OUTCOME-TWO-PLAN.md`, `.pi/outcome-two/capability-implementation-gate.md`, and the exact five capability implementation surfaces. Production was not changed.

## Verdict

**BLOCK.** There are unresolved P1/P2 findings. No capability workflow execution is authorized.

## P0

Explicitly no P0 findings.

## P1

### P1-1 — The portable suite does not drive the production state/syscall/process boundary or hostile lifecycle cuts

- `test/runner-capability-probe.test.ts:392-410` only launches `--self-test` and invalid command-line modes.
- `scripts/runner-capability-probe.py:1466-1525` shows that `--self-test` uses an in-memory report factory with only two booleans (`inject_cleanup_failure` and `inject_timeout`); it does not drive `Ledger`, tool resolution, child execution, fd operations, namespaces, mounts, procfs, seccomp, KVM, rlimit changes, or cleanup/recovery through a scripted adapter.

Consequently there is no hostile portable coverage for per-acquisition failures, open/dup/pipe/fork/exec/read/status/wait/reap/TERM/KILL failures, symlink loops or generation drift, malformed/overflow child records, fd exhaustion/reuse/double-close, multiple cleanup failures, poisoned repeat cleanup, baseline restoration, or crash recovery. This is the central portable qualification required by ADR 0087, not optional additional coverage.

### P1-2 — The “independent” semantics test accepts contract-invalid status records and checks only a small subset of report coupling

- `test/runner-capability-probe.test.ts:217-231` treats every `{state:"blocked", errno:null}` as valid without a named non-`ok` prerequisite or proof that the operation was not attempted, and treats `unsupported/errno:null` as valid in every context rather than only for an absent fixed object.
- `test/runner-capability-probe.test.ts:234-255` checks only cleanup/outcome, two source equalities, Python presence, and one low-fd postcondition.
- `test/runner-capability-probe.test.ts:318-364` mutates only one generic status location and six aggregate fields.
- The production validator itself only applies operation/postcondition checks to the cases listed at `scripts/runner-capability-probe.py:1437-1465`; the test therefore does not independently challenge the omitted sudo, user-map, combined namespace/proc, map-files, seccomp, KVM, cleanup-status, and tool metadata relationships.

Impossible combinations can pass the schema and this test while violating ADR 0087 C14. The required independent mutation matrix must cover every status/errno/postcondition and outcome/cleanup relationship.

### P1-3 — Two non-transferable per-file hard highs are exceeded

Gross additions from the exact predecessor are:

| Surface | Actual | Hard high | Result |
| --- | ---: | ---: | --- |
| `.github/workflows/outcome-two-runner-capability.yml` | 74 | 80 | within by 6 |
| `schemas/runner-capability-probe-v1alpha1.json` | 560 | 650 | within by 90 |
| `scripts/runner-capability-probe.py` | 1,596 | 1,600 | within by 4 |
| `test/runner-capability-probe.test.ts` | 411 | 400 | **over by 11** (`:401-411`) |
| `test/outcome-two-runner-capability-workflow.test.ts` | 103 | 100 | **over by 3** (`:101-103`) |
| **Aggregate** | **2,744** | **2,830** | within by 86 |

ADR 0087 makes these highs non-transferable, so aggregate headroom cannot cure either crossing. This is an immediate replan/stop condition.

## P2

### P2-1 — Workflow structure checks can miss an extra live-effect step

`test/outcome-two-runner-capability-workflow.test.ts:27` counts only lines having `- name:` rather than parsing and counting actual steps. The checks at `:95-102` also do not reject an unnamed additional `run:` step invoking, for example, `sudo`, `unshare`, or another host operation. Such a fourth step can retain three named steps and one `uses:` entry and evade the asserted structure. This defeats the static gate intended to prevent accidental live effects.

The exact current workflow has three named steps and no extra live-effect step; this finding is about the hostile/static test's inability to preserve that property.

### P2-2 — Optimized-mode rejection is implemented but not regression-tested

`test/runner-capability-probe.test.ts:393-406` always invokes `/usr/bin/python3 -I -B` without `-O`. It covers default/no-argument rejection at `:406-409`, but never executes optimized mode. The implementation check at `scripts/runner-capability-probe.py:1572-1573` currently rejects optimization, and a manual `/usr/bin/python3 -I -B -O ... --self-test` check exited 2 with empty stdout/stderr, but the required portable test would not catch removal of that guard.

### P2-3 — The required diff-format static gate is red

`git diff --check bec0a19b0b984f88ab9c2effc5059f3737915caa...HEAD` fails on trailing whitespace at:

- `.pi/outcome-two/capability-implementation-gate.md:3`
- `.pi/outcome-two/capability-implementation-gate.md:4`

Regardless of Markdown intent, the accepted gate explicitly requires this command to pass at the reviewed head.

## P3

Explicitly no P3 findings.

## Checks run

- Capability TypeScript tests: **PASS**, 6/6 after an offline dependency install.
- `/usr/bin/python3 -I -B scripts/runner-capability-probe.py --self-test`: **PASS**.
- Default/no-argument invocation: **rejected**, exit 2, empty stdout/stderr.
- Optimized self-test invocation: **rejected**, exit 2, empty stdout/stderr.
- `npm run format:check`: **PASS**.
- `npm run typecheck`: **PASS**.
- `npm run schemas`: **PASS** (15 registered schemas).
- `git diff --check <predecessor>...HEAD`: **FAIL** as reported in P2-3.

No reviewed test invoked real sudo, namespace creation, mount, proc `map_files`, seccomp, KVM, `close_range`, `O_TMPFILE`, compression tools, network, container, provider, cloud, or a workflow. The current invalid `--workflow-bound` test fails during public-control validation before those effects.

CAP-REVIEW-TESTS COMPLETE
