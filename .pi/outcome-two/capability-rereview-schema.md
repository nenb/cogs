# Outcome 2 capability schema/driver second hostile review

**Exact reviewed head:** `ab578313c50f52768003fa3416c514627ba1946d`  
**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`  
**Authorities:** accepted ADR 0087 and proposed/accepted correction ADR 0088  
**Prior-review inputs:** all five first capability reviews in `.pi/outcome-two/capability-review-{workflow,schema,driver,tests,holistic}.md`  
**Implementation reviewed:** the exact five capability surfaces; review only, with no production or workflow implementation changes

## Verdict

**BLOCK. The exact-head implementation still has unresolved P1–P3 findings.** The public report remains explicitly non-authoritative, UID/GID-map disclosure and forbidden envelope equality were corrected, and canonical top-level encoding remains bounded. However, the production validator still accepts impossible `outcome="complete"` reports, the required recovery topology and baselines are absent, the hostile test adapter does not drive production lifecycle control flow, and the schema still disagrees with the driver on the exact envelope numeric domains.

## Attempt-safety decision

**UNSAFE — DO NOT ATTEMPT.** A real effectful attempt is not safe at `ab57831`: the process performing effects is itself the only recovery supervisor; executable children can begin before parent registration/release; several case children never receive the fixed socket/io_uring filter; and mount, namespace, child, private-name, and checkout restoration are not proved against exact pre-effect baselines. Independently, ADR 0087/0088 supply no separate named approval for an exact-head, exact-blob, exact-event, attempt-1 public-log observation.

## P0

No findings.

## P1

### P1-1 — The production validator still accepts impossible complete reports

**Lines:**

- `scripts/runner-capability-probe.py:1250-1261`
- `scripts/runner-capability-probe.py:1270-1287`
- `scripts/runner-capability-probe.py:1288-1382`
- `test/runner-capability-probe.test.ts:334-529`

`validate_report()` now covers more fields, but it still does not enforce the complete ADR 0088 relationship matrix. A direct mutation challenge against the exact production validator accepted each of these while retaining `outcome="complete"` and all aggregate cleanup booleans:

1. `sudo.noninteractive=denied(EPERM)` while both sudo close-from cases remain `ok`;
2. `child_owned_proc_after_cap_drop.capability_sets_zero=false`;
3. a partial map open whose `first_open_failure` itself has state `ok`;
4. successful combined proc setup with `child_proc_read_only=null`;
5. a tool `mismatch` with every visible policy/postcondition still true, so no exact false postcondition exists;
6. hard `RLIMIT_NOFILE=1024` with null-errno `unsupported` high-fd status while high `close_range` remains `ok`; and
7. a KVM open/close-like `error` with downstream ioctls blocked but aggregate cleanup still complete.

The validator permits null-errno `unsupported` in every context at lines 1275-1277 even though ADR 0088 permits that form only for a proved absent fixed object. It does not couple sudo admission to the descriptor cases, the high-limit prerequisite to high `close_range`, before/after capability state, combined proc postconditions, KVM descriptor-close uncertainty, or a mismatch to an observable false postcondition. For map failures it validates only that a status is shaped correctly, not that `first_open_failure` is a genuine non-`ok` attempted failure.

The TypeScript validator catches some of these relationships, but the test mutation matrix calls only the TypeScript validator for them; it does not challenge `validate_report()`. Thus green tests conceal a production/test semantic split. This is the prior schema P1-2/P1-3 and holistic P1-3 finding only partially corrected.

### P1-2 — The required outer recovery topology and pre-release child identity contract are absent

**Lines:**

- `scripts/runner-capability-probe.py:192-197`
- `scripts/runner-capability-probe.py:238-292`
- `scripts/runner-capability-probe.py:293-335`
- `scripts/runner-capability-probe.py:344-374`
- `scripts/runner-capability-probe.py:1185-1196`
- `scripts/runner-capability-probe.py:1461-1475`

ADR 0088 requires a fixed outer subreaper/recovery supervisor and a separate effect worker. Here `probe_linux()` performs every effect in the same process that sets itself as subreaper. If that process is killed or crashes, there is no outer owner to recover its private names or verify cleanup.

`Ledger.run()` calls `subprocess.Popen()` and only registers the child after `Popen` returns. There is no release gate in this route, so `/usr/bin/unshare`, sudo, and Python helpers may execute case effects before `register_child()` obtains a pidfd/start-time/session identity. `ChildIdentity` also records no expected executable or process-group identity. Sudo can cross its privilege boundary before the in-memory root Python helper rearms PDEATHSIG.

The fork route has a gate, but `child_boundary()` only sets PDEATHSIG/session/cwd/environment/descriptors. It does not install the fixed socket/io_uring filter. Consequently tmpfile, mount, namespace, descriptor-limit, seccomp, and KVM case functions run after release without the required filter. These defects leave the original driver P1-1 and holistic P2-1 attempt-safety findings unresolved.

### P1-3 — Cleanup truth still lacks the required exact baselines and per-effect deadline enforcement

**Lines:**

- `scripts/runner-capability-probe.py:199-224`
- `scripts/runner-capability-probe.py:295-300`
- `scripts/runner-capability-probe.py:344-350`
- `scripts/runner-capability-probe.py:1185-1248`

The ledger captures only a descriptor snapshot and cwd inode generation. `mounts_gone` and `temporary_names_gone` begin true; there is no exact pre-effect child/descendant, mount-table, namespace, private-root-state, checkout-porcelain/content, or registry baseline. Finalization assigns `namespace_handles_retained=false` as a constant and treats a cwd generation comparison as checkout restoration. It therefore cannot prove the cleanup claims required by ADR 0088.

The 100-second effect cutoff is only a coarse `can_effect()` check. Case bodies such as tmpfile, mount, namespace, close-range, KVM, and their nested loops do not check the absolute deadline before every open/dup/pipe/read/write/syscall/status/wait operation. The implementation also allows 24 cumulative children at lines 295 and 345, while the accepted bound is 16. The prior driver P1-2/P1-3 and holistic P1-2 cleanup/deadline findings remain materially unresolved.

### P1-4 — The required portable fault matrix still does not drive production lifecycle code

**Lines:**

- `scripts/runner-capability-probe.py:1413-1458`
- `test/runner-capability-probe.test.ts:742-838`

`ScriptedOwner` is a separate six-string registry model. It does not instantiate or drive `Ledger`, `probe_linux`, `run`, `fork_case`, fixed-tool acquisition, process identity, deadline, baseline, mount/name authority, or production cleanup. The guard test proves only that this independent fake avoids real effects. It does not inject the required open/dup/pipe/pidfd/fork/exec/readiness/PDEATH/status/TERM/KILL/wait/reap and baseline failures into production control flow.

This is the prior tests P1-1/P1-2 and holistic P1-4 finding, not its resolution. It also explains why the P1-1 mutation acceptances and P1-2/P1-3 lifecycle defects pass the current seven tests.

## P2

### P2-1 — The corrected credential gate remains incomplete and has no executable credential challenge

**Lines:**

- `.github/workflows/outcome-two-runner-capability.yml:46-63`
- `test/outcome-two-runner-capability-workflow.test.ts:40-53`
- `test/outcome-two-runner-capability-workflow.test.ts:119-140`

Fetch/push URL checks and scoped/unscoped extraheader rejection were added. The gate still rejects only `credential.*.helper`, not every `credential.*` setting, and it does not reject `core.askPass` or nonempty `GIT_ASKPASS`/`SSH_ASKPASS` routes as ADR 0088 requires. The test remains static string/mutation inspection; it does not extract and execute the credential sub-gate in temporary Git repositories against the mandated canary cases. The prior workflow credential finding is only partially resolved, leaving the admission/disclosure proof incomplete.

### P2-2 — Internal categorical-record parsing is not the required strict canonical grammar

**Lines:**

- `scripts/runner-capability-probe.py:396-400`
- `scripts/runner-capability-probe.py:739-755`

Both helper-record parsers use ordinary `json.loads()`. They do not reject duplicate object keys or require canonical key order, compact separators, and exactly one LF. The fixed helpers normally emit compact sorted JSON, but ADR 0088 explicitly requires malformed, duplicate, extra, and noncanonical helper output to become mismatch/error and receive hostile coverage. The top-level report codec is canonical; the child/helper envelope is not strictly decoded.

## P3

### P3-1 — The schema still has the exact envelope numeric-domain mismatch identified by the first review

**Lines:**

- `schemas/runner-capability-probe-v1alpha1.json:120-123`
- `scripts/runner-capability-probe.py:1071-1107`
- `scripts/runner-capability-probe.py:1291-1294`
- `test/runner-capability-probe.test.ts:348-353`

ADR 0088 requires `run_attempt` to be exactly 1 and `pull_request_number` to be at most 2,147,483,647 everywhere. The driver and TypeScript semantics enforce those values, but the schema still allows attempts 2 through 255 and PR numbers through 9,999,999,999. Current schema mutations test only 256 and 10,000,000,000, so the disagreement passes. This is the original schema P3-1 finding and is unresolved.

## Prior-finding resolution audit

| First-review area | Exact-head disposition |
| --- | --- |
| Numeric UID/GID map disclosure | **Resolved.** Public schema/report contain only categorical map statuses and `exact_root_mapping`; old keys are rejected. |
| `github_sha == event_merge_sha` equality | **Resolved.** Driver and tests allow independently valid, distinct envelope identities. |
| Seccomp query failures fabricated as zero | **Resolved.** Initial values are nullable and separately status-coupled. |
| Child proc distinction never measured | **Resolved in implementation shape.** The helper now emits a categorical distinction boolean/status, subject to P1-1's incomplete surrounding proc coupling. |
| Root path component not authenticated | **Resolved.** `/` ownership/write policy is checked before later tool components. |
| Child cwd/environment/stdout/stderr leakage | **Partially resolved.** The boundary clears cwd/environment and redirects output, but P1-2's filter/readiness/recovery defects remain. |
| Cleanup/lifecycle/deadline findings | **Unresolved;** see P1-2 and P1-3. |
| Complete semantic coupling | **Unresolved;** see P1-1. |
| Credential gate | **Partially resolved;** see P2-1. |
| Portable production fault matrix | **Unresolved;** see P1-4. |
| Workflow actual-step counting and optimized-mode regression | **Resolved.** |
| Non-transferable line highs | **Resolved by ADR 0088 and current accounting.** |
| Exact-five-surface diff-format gate | **Resolved.** |
| Envelope numeric domains | **Unresolved;** see P3-1. |

## Areas with no additional finding

- Top-level report bytes use strict UTF-8 encoding, lexical object-key ordering, compact separators, integer-only values, exactly one LF, and the 32,768-byte bound.
- `authority="none"`, `qualified=false`, log-only retention, and no artifact/upload route remain intact.
- PR head/checkout, base SHA, `github.sha`, `github.workflow_sha`, and event merge SHA remain separately named; no equality/inequality is imposed among the five envelope identities.
- Public report/schema no longer contain tool-version output, numeric ID-map rows, resolved tool targets, PIDs, fds, mount/namespace IDs, maps text, or raw diagnostics.
- The schema is Draft 2020-12 and recursively closes report objects. Shape closure does not cure the semantic findings above.

## Line accounting

Gross additions from the exact predecessor remain within every corrected non-transferable ADR 0088 high:

| Surface | Gross additions | High |
| --- | ---: | ---: |
| `.github/workflows/outcome-two-runner-capability.yml` | 86 | 120 |
| `schemas/runner-capability-probe-v1alpha1.json` | 637 | 700 |
| `scripts/runner-capability-probe.py` | 1,488 | 1,900 |
| `test/runner-capability-probe.test.ts` | 852 | 900 |
| `test/outcome-two-runner-capability-workflow.test.ts` | 141 | 160 |
| **Aggregate** | **3,204** | **3,780** |

## Checks performed

- `/usr/bin/python3 -I -B scripts/runner-capability-probe.py --self-test` — passed.
- Optimized self-test — rejected with exit 2 and empty stdout/stderr.
- Capability TypeScript suites — passed, 7/7 after local dependency installation.
- `npm run schemas` — passed.
- `npm run format:check` — passed.
- `npm run typecheck` — passed.
- Exact-five-surface `git diff --check` from the accounting predecessor — passed.
- Direct production-validator hostile mutations — reproduced all seven P1-1 acceptances.

No capability workflow was triggered, no report was uploaded, and no production file was changed.

CAP-R2-SCHEMA COMPLETE
