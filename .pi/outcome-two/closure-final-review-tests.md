# Outcome 2 final trusted-closure hostile review — portable tests

- Review ID: `O2-FINAL-R-TESTS`
- Exact reviewed head: `3135c16add3abe1b32785f3d577cccd811ce5e54`
- Governing decision: accepted ADR 0089, with its non-conflicting ADR 0088/0087 boundaries
- Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- Scope: all seven portable Python suites, the TypeScript wrapper, every Outcome Two fixture, exact production-symbol reachability, tracked schema and independent report paths, crash/no-retry evidence, sentinels, portable effects, readability, and ADR 0089 highs
- Inputs read: all five first `closure-review-*.md` reports, all five `closure-rereview-*.md` reports, `.pi/outcome-two/closure-audit.md`, the complete second-correction acceptance gate, and ADR 0089
- Review host: Darwin 24.6.0 arm64; no native Job A–E, namespace, mount, chroot, seccomp, `map_files`, compression-tool qualification, provider, cloud, AWS, workflow, or deployment action was run

## Decision

**BLOCKED — two P1 and two P2 findings remain. Native Jobs A–E implementation is not ready to begin.**

The seven direct suites pass and reject optimized Python. The report suite genuinely enters the production tracked-schema method, producer decoder/re-encoder, and independent launcher decoder/re-encoder; its production report construction equals the golden bytes. The mapped suite now reaches the exact `ambiguous mapped fingerprint` and `mapped closure object bound` branches, and the source/report sealing matrices substantially drive their named production primitives. The obsolete `_drive_fixed_*`, `_T2_SEQUENCE`, and `_seal_source` routes are absent.

Those improvements do not close ADR 0089. The launcher ledger marks 127 rows proved without executing their fixture-selected production methods or primitive faults. Recovery executes only the 17 synthetic crash rows and then programmatically declares every remaining row consumed. Across the other ledgers, most `sentinel` fields remain labels rather than branch-removal oracles. The final fixture rename also avoids ordinary JSON formatting by giving multi-line whole-document JSON a `.jsonl` suffix while retaining 283–373-character packed rows.

## Findings

### P1-1 — The launcher suite launders 127 fixture rows through symbol existence and set insertion instead of executing their production predicates

**Files/lines:**

- `test/outcome-two-trusted-launcher-portable.py:47-87,252-306,309-432,435-464`
- `test/fixtures/outcome-two/launcher/cases.json:1-332`

`fixture_rows()` resolves each family’s `production_method` only far enough to prove it is callable. `source_reachability()` separately proves that selected top-level names occur in the `_bootstrap_main` AST call graph. Neither operation calls the fixture-selected method with `primitive_fault`.

The suite then runs five coarse predicate groups and, at lines 435–453, adds **every** row ID to `consumed`, `oracle`, and `sentinel` solely because its acceptance-ID prefix occurs in one of two static sets. The loop never reads `primitive_fault`, `production_method`, `intended_code`, `cleanup_domains`, or the sentinel’s production branch.

A focused AST diagnostic found 127 declared launcher rows. Among their exact family methods, the suite directly calls only `_descriptor_snapshot`, `_enter_boundary`, and `_seccomp_digest`; it does not directly drive `_bootstrap_with_ops`, `_authenticate_sources`, `_load_private_closure`, `_WorkerIssuer._accept_runtime_closure`, `_consume_issuance`, `_verify_bundle`, `_run_tool_with_ops`, `_coordinate_with_ops`, `_materialize_root`, `_ProcessOwner.register`, `_ProcessOwner.cleanup`, or `_recv_status`. The narrow direct calls to `_WorkerIssuer._consume_runtime_closure_capability`, `_credentials`, `_FdLease.close`, and `_ObservedFacts` cover only a handful of hand-built cases, not the corresponding fixture matrices.

Consequently the exact status/exec/final-map/input gates, issuance packet/EOF variants, generation rows, user-map ordering, root cuts, process ownership, record mutations, typed unavailability, bootstrap loading, and mutable T2 observations can be removed or broken while all 127 rows remain “proved.” This is the label-player defect in a ledger-only form and fails `AT-ADAPT-BOOT-01`, `AT-ADAPT-ISSUE-01`, `AT-ADAPT-T2-01`, and `AT-FIXTURE-01`.

### P1-2 — Recovery proves one bounded synthetic process cleanup, not crash recovery at the declared authority-bearing production cuts

**Files/lines:**

- `test/outcome-two-recovery-portable.py:125-197,254-301`
- `test/fixtures/outcome-two/recovery/cases.json:1-98`

Only the 17 `AT-ADAPT-REC-01` rows are selected for execution. For each, the test forks the same pipe-only child, writes the selected cut string, stops it, manually appends a fabricated `_ProcessLease`, and monkeypatches `_process_matches` plus `signal.pidfd_send_signal` before calling `_recover_transaction_with_ops`. The child never enters `_coordinate_with_ops`, `_worker_main`, closure preparation/issuance, `_materialize_root`, helper registration, mount ownership, or namespace ownership. The cut is a marker string, not a fault at a production write-ahead branch.

Lines 277–285 then compute `remaining = selected - consumed` and immediately add all remaining IDs to `consumed`, `oracle`, and `sentinel`. Thus none of the five `AT-ROOT-01` rows, four `AT-LIFE-01` rows, six `AT-LIFE-02` rows, four `AT-FD-CLOSE-01` rows, or three `AT-UNAV-01` rows is executed according to its row. The separate single close-uncertainty and typed-unavailable demonstrations cannot establish those 22 distinct intended codes and cleanup domains.

The suite does establish a useful narrow fact: one released child is killed/reaped and preparation is not retried (`retry.prepare` is statically banned). It does **not** establish the accepted “real authority-bearing inner worker crashed at every write-ahead cut while a surviving outer owner recovers the exact worker/helper/root/mount/namespace transaction” contract. `AT-ADAPT-REC-01` and the recovery portions of `AT-ROOT-01`/`AT-LIFE-01` remain open.

### P2-1 — Most six-key fixture sentinels are metadata labels, not exact production branch-removal oracles

**Files/lines:**

- `test/outcome-two-runtime-closure-portable.py:299-345`
- `test/outcome-two-sealing-portable.py:255-264`
- `test/outcome-two-lifecycle-portable.py:512-537`
- `test/outcome-two-runtime-report-portable.py:150-177,285-313`
- `test/outcome-two-trusted-launcher-portable.py:435-453`
- `test/outcome-two-recovery-portable.py:277-285`
- `test/fixtures/outcome-two/lifecycle/faults.jsonl:3-64`
- `test/fixtures/outcome-two/reports/mutations.jsonl:3-37`

The closure and sealing suites assign `sentinel = list(executed)` without reading any row sentinel. Lifecycle verifies only that `production_method` and `sentinel` are nonempty; its `production_method` values are compound labels such as `closure._snapshot_fds + launcher._descriptor_snapshot`, and its intended rejection code is the generic string `typed-rejection`. The report fixture similarly names labels such as `closure._construct_report/schema/producer/consumer` and `schema/producer/consumer strict framing`; the suite checks that sentinels are nonempty but never resolves them to production symbols or proves removal of the named branch makes that row fail. Launcher and recovery synthesize sentinel sets from IDs as described above.

The mapped suite is a positive exception for the two gate-critical cases: it requires the exact production messages `ambiguous mapped fingerprint` and `mapped closure object bound`. Other mapped rows still use type-level oracles only.

The on-disk shape is also not uniformly the declared six-key row contract: lifecycle rows add a seventh `expect` field, while launcher/recovery store family metadata plus two-element case tuples and manufacture six-key rows in test code. Selector equality and exception type are useful, but they are not the mandatory per-row branch-removal sentinel. In particular, the required `same-inode`, `double-close`, `unexpected-owned-child`, `spawn-after`, and `cleanup-after-poison` claims lack independent named-branch sentinels even where their broad runners now execute production methods.

### P2-2 — The final fixture rename evades ordinary formatting and leaves cap-compressed, non-JSONL ledgers

**Files/lines:**

- `test/fixtures/outcome-two/closure/cases.jsonl:1-34`
- `test/fixtures/outcome-two/lifecycle/faults.jsonl:1-66`
- `test/fixtures/outcome-two/maps/cases.jsonl:1-28`
- `test/fixtures/outcome-two/reports/mutations.jsonl:1-39`
- `test/fixtures/outcome-two/sealing/faults.jsonl:1-59`
- exact-head commit `3135c16` (`Keep compact hostile fixture ledgers formatter-safe`)

These files are not JSON Lines: each is one multi-line JSON document and the suites parse it with `json.loads(...read_text())`. Renaming them from `.json` to `.jsonl` removes ordinary JSON formatter coverage without changing the packed representation. Individual rows remain 283–373 characters long with the six security fields compressed onto one physical line.

This is especially material because `test/outcome-two-runtime-closure-portable.py` is exactly 350/350 gross lines and ADR 0089 expressly makes ordinary readable formatting a security acceptance property rather than a cap-evasion option. The wrapper’s narrow regex gate passes, but it cannot establish human readability, and the exact-head rename is formatting avoidance rather than formatting compliance. `AT-READABLE-01` remains open.

## Seven-suite and fixture disposition

| Suite | Actual production evidence | Final disposition |
| --- | --- | --- |
| Runtime closure | Extensive `parse_elf64`, `_resolve_tool`, bound, and alias-policy execution | Substantial; sentinels remain metadata/type-level except direct behavior assertions |
| Mapped closure | Every row drives `_mapped_closure`; both required named bound branches are exact | Strongest fixture binding; most non-bound sentinels remain type-level |
| Sealing | Every row drives `_seal_object` or `_seal_report` through primitive faults | Substantial; row sentinel is never consumed |
| Lifecycle | Broad direct execution of closure/launcher fd and helper methods | Substantial model coverage; compound production labels and no branch-removal sentinel |
| Recovery | `_recover_transaction_with_ops` cleans one real local child shape | **Overclaimed:** 17 cut labels are not production cuts; 22 rows are never row-executed |
| Runtime report | Production construction plus tracked schema, producer codec, consumer codec; exact golden | Strong three-path semantics; fixture production methods/sentinels are labels |
| Trusted launcher | A few exact admission/ancillary/fd/boundary primitives plus AST reachability | **Overclaimed:** 127 rows are marked proved without per-row production execution |

## Schema and codec result

The direct report suite passed and verified three distinct production code objects:

1. `launcher._SourceAdmission._validate_tracked_schema` -> `_validate_tracked_report`;
2. `closure._producer_decode_report` plus `_producer_reencode_report`; and
3. `launcher._decode_report` plus its consumer re-encoder.

`closure._construct_report` entered the production schema callback and reproduced the canonical golden bytes. Every semantic and encoding mutation was sent through those three Python paths. By inspection, `test/outcome-two-portable.test.ts` sends the same semantic corpus through AJV 2020 against the tracked schema. AJV execution was unavailable on this host because locked `node_modules` is absent; no `npm install` or network action was attempted.

## Checks

| Check | Result |
| --- | --- |
| Exact `HEAD` before report | **PASS** — `3135c16add3abe1b32785f3d577cccd811ce5e54` |
| Seven direct `env -i ... /usr/bin/python3 -I -B` suites | **PASS** |
| Seven optimized `-O -I -B` runs | **PASS gate** — all rejected optimized Python |
| In-memory compile of three production modules and seven suites | **PASS**; no bytecode/cache created |
| Focused launcher/recovery exact-call diagnostic | **FAIL contract** — 127 launcher rows are not per-row invoked; recovery row-executes only 17/39 |
| Tracked schema + producer + consumer direct corpus | **PASS** in the report suite |
| TypeScript AJV wrapper | **NOT RUN / environment blocked** — `tsx`/AJV dependencies absent |
| `npm run schemas`, `typecheck`, `format:check` | **NOT RUN / environment blocked** — local `tsx`, `tsc`, and `biome` absent (each exited 127) |
| ADR 0089 dead-route/packing regex gate | **PASS** |
| `git diff --check` for accepted surfaces and exact-head commit | **PASS** |
| `git fsck --no-progress --no-dangling` | **PASS** |
| Portable effect audit | **PASS with disclosure** — no privileged/native/security primitive; recovery alone uses a bounded local fork/STOP/KILL/reap child |
| Cache/worktree residue before report | **PASS** — none |

### Exact gross highs

All measured additions from `bec0a19...` are within ADR 0089:

- parser 306/320;
- closure 2,078/2,100;
- launcher 1,889/1,900;
- schema 134/260;
- schema registration 27/30;
- seven suites 350/350, 256/300, 265/300, 538/550, 308/550, 326/400, 471/800;
- TypeScript wrapper 155/170;
- fixture aggregate 680/900; and
- trusted/portable subtotal 7,783/8,930.

Numeric compliance does not cure P2-2.

## Native implementation readiness

**NOT READY.** ADR 0089 requires a fresh exact-head review with no unresolved P0–P3 before native implementation begins. The green output currently permits the launcher and recovery acceptance catalogs to pass without fixture-selected production execution and without exact sentinels. Native Jobs A–E cannot repair or substitute for that portable gate.

No native, integration, AWS, provider, deployment, production, release, or issue-closure authority is granted by this report.

O2-FINAL-R-TESTS COMPLETE
