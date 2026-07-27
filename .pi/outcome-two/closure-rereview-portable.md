# Outcome 2 trusted-closure second hostile review — portable tests

**Disposition:** **BLOCKED — unresolved P0–P2; not ready for native Jobs A–E**  
**Exact reviewed head:** `d845cb13111cc3077141d84a3796537bd125dd0b` (`d845cb1`)  
**Accepted authority:** ADR 0088, with non-conflicting ADR 0087 rules  
**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`  
**Scope:** all five first closure reviews, all four correction designs, ADR 0088, the three corrected production modules, schema/registration, all seven portable suites, their wrapper, and every Outcome 2 fixture. Review only; no production, schema, test, or fixture was changed.

## Executive result

The correction materially improves the ELF page model, held-source sealing, exact fd enumeration in the closure owner, report mutation construction, one-shot fd leases, and the shape of the admitted bootstrap/SCM_RIGHTS/T2 implementation. All seven direct portable suites pass, all seven reject optimized Python, their fixture ID ledgers are selector-complete, and the direct runs perform no privileged/native effects.

The gate is nevertheless not closed. The launcher and crash suites drive parallel label interpreters rather than the production bootstrap, issuer, sandbox, launcher lifecycle, or outer coordinator. Several fixture rows execute but do not reach their named predicate. More importantly, production still publishes all-true T2 and cleanup facts after multiple “observations” that are no-ops in `_SystemOps`; its namespace child has unbounded/raw-PID cleanup paths, and its outer coordinator does not retain the authority required to recover a crashed closure worker. The green portable result therefore overclaims the production boundary.

## Findings

### P0-1 — Production can publish a successful T2 result without observing the facts represented by its true fields

**Exact lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:263-269` makes `_security_operation()` return `None` when `_SystemOps` is used and no effect callback is supplied.
- `launcher.py:733-736` performs one combined `unshare`, but the PID/mount/network “checks” are label-only calls. No namespace identity or ownership is observed.
- `launcher.py:688-690` labels three capability-set checks without operations; `:699-700` labels io_uring, namespace, mount, seccomp-replacement, and acquisition denials without executing or observing a probe.
- `launcher.py:755-759` labels `child.pid-one` and then performs a blocking wait; it does not prove the child is PID 1 in the intended namespace.
- `launcher.py:988-994` checks only child-record bytes, the fd snapshot, and root-path absence before `:995-1000` constructs `RuntimeQualificationResult` with every mapping, namespace, PID-1, capability, seccomp, descendant, mount, and path field hard-coded `True`.

This is the exact result-overclaim ADR 0088 forbids. A real `unshare` or seccomp installation does not prove namespace identity, every capability set, the named denial behavior, descendants, or cleanup. The production route can therefore emit authoritative-looking success for unobserved security facts. P0-3 from the first review is not resolved.

### P1-1 — The launcher portable routes are parallel label programs, not adapters for production bootstrap/issuer/T2 methods

**Exact lines:**

- Production bootstrap/coordination runs through `launcher.py:1246-1279`, `_WorkerIssuer`/`_consume_issuance` at `:458-518,574-612`, root/T2/tool execution at `:647-934`, and `_coordinate` at `:962-1027`.
- The tested routes instead live at `launcher.py:1043-1094`. Bootstrap merely iterates every attack name; issuer success likewise iterates every attack name before returning a prebuilt consumed outcome; T2 replays `_T2_SEQUENCE`, force-releases model sets, and assigns every claim `True` at `:1085-1088`.
- `test/outcome-two-trusted-launcher-portable.py:83-114` rejects a case because the **test adapter itself** raises when a matching string is encountered. `:155-225` calls only the three label routes. It never calls or primitive-adapts `_bootstrap_main`, `_authenticate_sources`, `_WorkerIssuer`, `_consume_issuance`, `_materialize_root`, `_namespace_owner`, `_run_one_tool`, or `_coordinate`.

Thus all declared bootstrap and issuer attacks and all T2 cuts are behavior-dead with respect to the production mechanisms they name. Forced removal from adapter sets is not evidence that production cleanup succeeded. ADR 0088 P1-6 remains open, and the first P0 source/issuer corrections cannot receive portable sign-off from this suite.

### P1-2 — “Crash recovery” now uses a real process and no retry, but still does not recover a crashed production authority owner

**Exact lines:**

- `launcher.py:1095-1138` forks a harmless pipe-blocked process, emits the selected crash-cut label, then kills/reaps the same empty worker. Every successful case subsequently iterates every recovery-fault label at `:1116-1119`.
- The process never enters `_worker_main`, `_coordinate`, closure preparation, helper creation, report issuance, namespace construction, or mount ownership. No declared crash cut corresponds to a production state transition.
- `test/outcome-two-recovery-portable.py:303-319` verifies one attempt and no `retry.prepare`, which correctly proves **not retry**, but it cannot prove recovery of descriptor/child/namespace/mount authority.
- Actual `_coordinate` at `launcher.py:962-979` registers only the closure worker after fork. The worker privately enters closure preparation at `:935-961`; there is no write-ahead registration of the worker’s helpers or pending authority with the outer coordinator.

The prior “fresh success is recovery” defect is narrowly removed, but the accepted real outer-supervisor contract is not implemented or tested. ADR 0088 P1-1 remains open.

### P1-3 — Launcher child identity and reap authority are still discarded or bypassed

**Exact lines:**

- `_stop_process()` appends identity/reap failures and then unconditionally closes the pidfd at `launcher.py:553-573`, including when the process may still be live.
- `_namespace_owner()` uses unbounded `waitpid(child, 0)` at `:757`; its failure path uses raw `kill` plus another blocking `waitpid` at `:770-775`.
- `_run_one_tool()` registers the namespace child but closes that child’s pidfd immediately after mapping at `:859-865`. Its final handling merely calls raw `waitpid(..., WNOHANG)` at `:928-932`; it has no exact descendant owner.
- None of these functions is entered by the launcher portable suite (P1-1).

This preserves the first review’s bounded-wait, retained-identity, descendant, and no-residue blockers. A timeout or identity error can return after discarding recovery authority.

### P1-4 — The launcher fd baseline reintroduces a transient enumeration descriptor

**Exact lines:** `launcher.py:243-250`.

The closure owner correctly calls `getdents64` on its explicitly opened directory fd and excludes that exact fd. The launcher instead passes the fd to `os.listdir()`. CPython must create/own a directory stream for this call, so the proc snapshot may contain its transient duplicate while the code excludes only `directory`. That transient number is closed when `listdir` returns and can differ on the next snapshot—the original Linux `READY`-baseline failure in launcher form. No portable test calls `_descriptor_snapshot`; T2’s synthetic baseline operations return empty sets (`test/outcome-two-trusted-launcher-portable.py:51-64`). ADR 0088 P1-3 is only resolved in the closure module, not the complete production route.

### P2-1 — Fixture IDs are all appended, but several declared predicates are dead, coupled, or contradictory

**Closure bounds:** `test/outcome-two-runtime-closure-portable.py:292-325` explicitly skips four manifest rows from `FsOps`/`_resolve_tool`, then calls pure bound helpers or constructs already-resolved dataclasses. Those rows do not execute the declared production primitive-adapter path or the three-tool orchestration at `closure.py:1597-1606`.

**Mapped closure:** `test/outcome-two-mapped-closure-portable.py:186-199` builds the 129-object case from 129 copies of the same ELF bytes. It is rejected by `ambiguous mapped fingerprint`, not an object bound; `_mapped_closure` itself has no 129-object gate at `closure.py:1104-1151`. The declared `ambiguous-fingerprint` case also rejects as `unknown or changed executable mapping`, because `:183-185` collapses two roles onto one expected identity. The test accepts any exception at `mapped-closure-portable.py:203-220` and never checks the intended code. A direct diagnostic at this head produced:

```text
ambiguous-fingerprint RuntimeClosureError unknown or changed executable mapping
mapping-object-bound RuntimeClosureError ambiguous mapped fingerprint
```

**Lifecycle:** `test/outcome-two-lifecycle-portable.py:360-381` marks `double-close`, `unexpected-owned-child`, and `cleanup-after-poison` executed without obtaining the fixture’s declared reject behavior: double close is accepted as an idempotent no-op, unexpected child only asserts that a hand-built process is live, and cleanup-after only proves an ordinary lease reached `CLOSED`. `:301-305` explicitly exempts `spawn-after` from retained recovery authority even though the model has created a live process.

**Child setup:** the model’s `clone3_pidfd()` always returns the parent PID, so the production child branch at `closure.py:911-933` is never entered. The ambient-fd row compensates by calling `_close_complement()` separately at lifecycle test lines `288-291`; this does not prove the actual child setup uses it correctly under each partial state.

The final `declared == executed` comparisons prove selector bookkeeping only. They do not prove one intended predicate, consumed primitive faults, closed fixture keys, or cleanup domains as required by the correction matrix.

### P2-2 — AJV and two codecs are present, but the production schema gate is outside the declared Python corpus

**Resolved portions:**

- `test/outcome-two-runtime-report-portable.py:41-118` recomputes dependent digests, so the old stale-digest coupling is substantially corrected.
- The Python suite calls the producer codec and independently implemented launcher consumer at `:186-207`.
- The TypeScript wrapper compiles the tracked schema with AJV 2020 and applies the emitted golden/semantic corpus at `test/outcome-two-portable.test.ts:59-82`.

**Remaining gap:** the Python suite never calls `_SourceAdmission._validate_tracked_schema` (`launcher.py:71-74`) or `_apply_schema_validator` (`closure.py:1346-1351`), and none of the seven suites calls the available full `_prepare_with_adapter_for_tests` route at `closure.py:1680-1684`. `scripts/validate-schemas.ts` contains only six hand-built closure mutations rather than the exact corpus. A one-off static diagnostic in this review did run the production schema gate over the emitted corpus and found no expectation divergence, but that is reviewer evidence, not an enforced repository test.

AJV itself could not be executed on this host because locked dependencies/`tsx` are absent. Therefore the AJV wiring is credible by inspection but not a green check in this review environment.

### P2-3 — Numeric highs pass, but cap-driven compressed security control flow remains

ADR 0088 requires ordinary readable formatting and explicitly forbids hiding multiple fallible security decisions on one physical line. The launcher is at 1,296/1,300 and the closure owner at 1,696/1,700. Examples include grouped imports/constants at `launcher.py:4-45`, semicolon-compressed security dataclasses at `:62-93`, and multi-operation report/closure expressions such as `closure.py:1331-1335,1606`. The numeric table is green, but the prior readability disposition is not.

### P3

No new standalone P3 finding. The historical predecessor-wide trailing whitespace was explicitly dispositioned by ADR 0088. Both the ADR-acceptance correction range and exact-head commit pass `git diff --check`.

## Seven-suite production-adapter status

| Suite | Declared rows selected once | Production primitive/state machine actually driven | Review result |
| --- | --- | --- | --- |
| runtime closure | Yes | Parser/resolver mostly; four closure/aggregate rows bypass primitive orchestration | **Partial** |
| mapped closure | Yes | `_mapped_closure` runs, but two named predicates reject elsewhere | **Partial / overclaimed** |
| sealing | Yes | `_seal_source` and `_seal_report` run through primitive models | **Substantial narrow coverage** |
| lifecycle | Yes | Narrow fd/helper methods run; child branch/full preparation and several cleanup rows are dead | **Partial / overclaimed** |
| recovery | Yes | Report seal and handoff cuts run; crash route is a separate empty-worker harness | **Crash claim not covered** |
| runtime report | Yes | Producer and consumer codecs run; AJV is in wrapper; production schema gate is not in suite | **Partial** |
| trusted launcher | Yes | Only label interpreters run, not production bootstrap/issuer/T2 | **Not production-bound** |

The requested statement that all seven suites/fixtures execute declared cases against production primitive adapters is false at `d845cb1`.

## Prior-review closure status

| Prior blocker | Second-review status |
| --- | --- |
| Pre-effect authenticated source loading | Candidate production route exists; portable bootstrap attacks are label-only, so **not signed off** |
| Forgeable/substitutable raw handoff | SCM_RIGHTS/nonce/binding code exists; all hostile cases are label-only, so **not signed off** |
| Actual T2 and final execution generations | Materialization/mapping code exists; P0-1 result overclaim and P1 lifecycle remain, so **unresolved** |
| Fresh retry mislabeled recovery | Fresh retry removed, but production-authority recovery is absent; **unresolved** |
| Exact child/descendant lifecycle | **Unresolved** (P1-3) |
| Linux fd enumeration baseline | Closure corrected; launcher still defective/uncovered; **partial** |
| Close uncertainty | Closure leases/report sealing materially corrected; launcher still closes retained process authority after uncertainty; **partial** |
| Page-granular ELF contract | Broad new direct parser matrix and 306/320 parser implementation; **materially resolved portably** |
| Schema plus independent codecs | AJV wiring and two codecs exist; production gate enforcement test missing; **partial** |
| Dead fixture truth | Selector equality added; intended-predicate and production-path truth still fail; **unresolved** |
| P3 historical whitespace | **Dispositioned by accepted ADR 0088; no new defect** |

## Measured line highs

Gross additions from `bec0a19...`; files were absent there except the schema registration addition. Fixture count uses current LF/physical convention and includes binary fixture LF bytes.

| Surface | Measured | ADR 0088 high | Margin |
| --- | ---: | ---: | ---: |
| `completion_elf.py` | 306 | 320 | 14 |
| `completion_trusted_runtime_closure.py` | 1,696 | 1,700 | 4 |
| `completion_trusted_runtime_launcher.py` | 1,296 | 1,300 | 4 |
| trusted closure schema | 134 | 260 | 126 |
| `validate-schemas.ts` Outcome 2 addition | 27 | 30 | 3 |
| runtime-closure portable | 336 | 350 | 14 |
| mapped-closure portable | 232 | 300 | 68 |
| sealing portable | 250 | 300 | 50 |
| lifecycle portable | 394 | 400 | 6 |
| recovery portable | 378 | 400 | 22 |
| runtime-report portable | 225 | 300 | 75 |
| trusted-launcher portable | 238 | 500 | 262 |
| TypeScript wrapper | 83 | 150 | 67 |
| `test/fixtures/outcome-two/**` | 433 | 700 | 267 |
| **Trusted/portable subtotal** | **6,028** | **7,010** | **982** |

No numeric high is crossed. The trusted closure/launcher and lifecycle suite have only 4/4/6 lines respectively; unused subtotal margin is non-transferable. Readability remains a finding under P2-3.

## Checks run

Review host: Darwin 24.6.0 arm64; `/usr/bin/python3` 3.9.6. No Linux native primitive, sudo, namespace, mount, chroot, seccomp, compression tool, network, provider, cloud, AWS, deployment, or workflow action was invoked.

| Check | Result |
| --- | --- |
| Exact head | **PASS** — `d845cb13111cc3077141d84a3796537bd125dd0b` |
| Seven direct `env -i ... /usr/bin/python3 -I -B` suites | **PASS** |
| Seven optimized `-O -I -B` rejection runs | **PASS** — every suite exited 1 |
| Python AST/compile check for production plus seven suites | **PASS**; generated caches removed |
| All fixture/schema JSON parsing | **PASS** |
| Production tracked-schema gate against emitted semantic corpus | **PASS** in reviewer diagnostic |
| Named map-predicate diagnostic | **FAIL contract** — both named cases reject for a different reason, quoted in P2-1 |
| `git diff --check 32ba6e0..d845cb1` and exact correction commit | **PASS** |
| `npx tsx --test test/outcome-two-portable.test.ts` | **NOT RUN / environment blocked** — `node_modules/.bin/tsx` absent |
| `npm run schemas` | **NOT RUN / environment blocked** — locked TypeScript dependencies absent |
| Portable privileged-effect audit | **PASS** — only bounded local subprocess/fork/kill mechanics; no privileged/native effect |
| Worktree before report | **Clean** |

## Native readiness

**NOT READY. Do not begin Jobs A–E or thin integration.** Native execution may qualify kernel availability only after the portable suites drive the actual production bootstrap, issuer, lifecycle, T2, and recovery state machines and after production stops publishing unobserved true facts. Native jobs must not repair or paper over P0-1, P1-1 through P1-4, or the dead intended predicates.

O2-R2-TESTS COMPLETE
