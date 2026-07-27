# Outcome 2 capability implementation — holistic hostile review

**Reviewed head:** `9c86bc5add169fadd86574fd8468422a46ee3ed0`  
**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`  
**Authorities:** accepted ADR 0087, `OUTCOME-TWO-PLAN.md`, and `.pi/outcome-two/capability-implementation-gate.md`  
**Implementation reviewed:** the exact five capability surfaces named by ADR 0087  
**Production changes:** none made by this review

## Verdict

**BLOCK. One real non-authoritative attempt is not safe.** The implementation has unresolved P1/P2 findings, exceeds two non-transferable per-file highs, and has not received the separate exact-head/event/blob/public-log approval required by ADR 0087. Do not apply the label or dispatch/rerun an observation.

## P0

No P0 findings.

## P1

### P1-1 — The driver reintroduces a forbidden equality between distinct GitHub envelope identities

- `.github/workflows/outcome-two-runner-capability.yml:70-73` correctly passes `github.sha`, `github.workflow_sha`, and event `merge_commit_sha` separately.
- `scripts/runner-capability-probe.py:1085-1092` then rejects the observation unless `github_sha == merge_sha`.
- `test/runner-capability-probe.test.ts:248-254` independently codifies the same equality instead of testing that the values remain separately named.

ADR 0087 requires those identities to remain separate and does not authorize equality (`docs/adr/0087-prepare-runtime-closure-before-capability-drop.md:174-181`). Historical hosted observations already motivated that distinction. A valid labeled event with distinct envelope values would fail before producing a report and consume the sole approved attempt. Remove the equality assumption and validate each value only against its own source/envelope meaning.

### P1-2 — Cleanup truth is optimistic rather than baseline-proved, and timeout paths can abandon live children

- `scripts/runner-capability-probe.py:130-140` initializes all cleanup claims to success without recording fd, mount/namespace, private-root, checkout, or child-identity baselines.
- `scripts/runner-capability-probe.py:225-233` marks reap uncertainty after a timed-out wait but unconditionally removes the possibly live PID from the only registry.
- `scripts/runner-capability-probe.py:257-321` ignores pipe-close results, uses PID/process-group signaling without pidfd/start-time/session revalidation, and can block in an unbounded `waitpid(pid, 0)` after the case deadline.
- `scripts/runner-capability-probe.py:1060-1061` ignores the KVM descriptor close result.
- `scripts/runner-capability-probe.py:1124-1159` owns and deletes fixed temporary paths by pathname/global boolean, not retained parent descriptors plus identity.
- `scripts/runner-capability-probe.py:1191` records only `RLIMIT_NOFILE`; `scripts/runner-capability-probe.py:1287-1297` converts the optimistic booleans directly into a potentially complete cleanup report.

This violates the gate's registration, exact cleanup, aggregation, and restored-baseline requirements. A close error, replaced path, or child that survives a wait timeout can coexist with an emitted cleanup claim or be left to runner disposal. That makes the effectful attempt unsafe even though its metadata has authority `none`.

### P1-3 — Production and independent semantic validation accept impossible complete reports

- `scripts/runner-capability-probe.py:804-818` labels any decoded sudo fd result `invocation=ok`, including results where required fd postconditions are false.
- `scripts/runner-capability-probe.py:1391-1465` validates only a subset of cross-field semantics. It omits sudo close-from results, seccomp prerequisite/result coupling, KVM coupling, user/combined namespace coupling, procfs counts/failures, and several cleanup/status relationships.
- `test/runner-capability-probe.test.ts:234-255` checks only cleanup, source/merge equality, Python, and one low-fd postcondition; it is not an independent whole-report semantic validator.
- `schemas/runner-capability-probe-v1alpha1.json:457-490` constrains each status locally but cannot supply the missing operation/postcondition/prerequisite coupling.

Direct review confirmation showed `validate_report()` accepts both (a) `sudo.close_from_3.invocation=ok` with `fd3_closed=false`, and (b) successful seccomp installation after `set_no_new_privs` is `denied`. Such reports may still be `outcome=complete` because `scripts/runner-capability-probe.py:1297-1302` derives completion only from cleanup. This violates ADR 0087 C14 and makes the observation semantically unreliable.

### P1-4 — Required portable hostile qualification is absent

- `scripts/runner-capability-probe.py:1466-1508` provides only a preassembled report fake; it is not a scripted syscall/process adapter driving production acquisition, child, mount, fd, and cleanup control flow.
- `scripts/runner-capability-probe.py:1509-1566` tests report encoding plus only two synthetic flags.
- `test/runner-capability-probe.test.ts:258-365` exercises schema/status mutations, while `test/runner-capability-probe.test.ts:367-411` performs static source checks and invokes only that shallow self-test.

There are no injected acquisition cuts for open/dup/pipe/fork/exec/read/wait/TERM/KILL/reap, no symlink-generation fault matrix, no close/unmount/unlink/rlimit/baseline aggregation matrix, and no production state-machine recovery exercise. ADR 0087 explicitly requires scripted adapters, hostile lifecycle/cleanup cuts, and independent semantic mutations (`docs/adr/0087-prepare-runtime-closure-before-capability-drop.md:221-235`). Green happy-path/static tests cannot authorize a real effectful attempt.

### P1-5 — Two exact non-transferable file highs are exceeded

Gross physical additions from exact predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa` are:

| Surface | Current | ADR 0087 high | Result |
|---|---:|---:|---|
| `.github/workflows/outcome-two-runner-capability.yml` | 74 | 80 | within |
| `schemas/runner-capability-probe-v1alpha1.json` | 560 | 650 | within |
| `scripts/runner-capability-probe.py` | 1,596 | 1,600 | within |
| `test/runner-capability-probe.test.ts` | 411 (`:1-411`) | 400 | **11 over** |
| `test/outcome-two-runner-capability-workflow.test.ts` | 103 (`:1-103`) | 100 | **3 over** |
| **Total** | **2,744** | **2,830** | within |

ADR 0087 makes each file high non-transferable and requires a new ADR before crossing one (`docs/adr/0087-prepare-runtime-closure-before-capability-drop.md:290-307,351`). Aggregate headroom cannot cure either overage. Implementation review must stop.

## P2

### P2-1 — Forked case children do not receive the promised closed, filtered boundary

`scripts/runner-capability-probe.py:257-280` forks in-process, closes only one pipe end, and does not clear inherited descriptors/environment, change away from the checkout working directory, redirect inherited stdout/stderr, or install the fixed socket/io_uring filter before `function()` runs at line 271. Those children execute irreversible tmpfile, mount/namespace, descriptor-limit, seccomp, and KVM cases via `scripts/runner-capability-probe.py:1201-1234,1268-1276,1337-1345`.

Consequently a case child retains ambient access to the checkout and public controls, and unexpected child output can reach the GitHub log instead of the categorical pipe. This conflicts with ADR 0087's C7/T2/C15 isolation and disclosure contract (`docs/adr/0087-prepare-runtime-closure-before-capability-drop.md:183-191,202-206`).

## P3

No P3 findings.

## Checks performed

After `npm ci` installed the locked dependencies:

- `/usr/bin/python3 -I -B scripts/runner-capability-probe.py --self-test` — pass.
- `npx --no-install tsx --test test/runner-capability-probe.test.ts test/outcome-two-runner-capability-workflow.test.ts` — 6/6 pass.
- `npm run schemas` — pass, 15 schemas.
- `npm run format:check` — pass.
- `npm run typecheck` — pass.
- `git diff --check` over the exact five implementation surfaces — pass.
- Gross-addition accounting from the accepted predecessor — 2,744 total; two per-file highs exceeded as above.

These checks do not resolve the findings because the required fault-driven portable coverage and semantic checks are not present.

## Attempt authority decision

**No attempt.** In addition to the implementation blockers, no reviewed material supplies the separate named approval binding this exact clean head, the exact workflow/driver/schema blobs, one labeled event, attempt 1, and public-log disclosure. ADR 0087 expressly says its acceptance authorizes no attempt (`docs/adr/0087-prepare-runtime-closure-before-capability-drop.md:202-206,221-235,353-363`).

CAP-REVIEW-HOLISTIC COMPLETE
