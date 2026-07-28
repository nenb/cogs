# ADR 0092 fresh exact-head holistic hostile review

- **Exact reviewed head:** `3846383f0d88c190226356ca9aeeeda402943aaa`
- **Branch:** `review/o2-92-holistic`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Authority reviewed:** accepted ADR 0092, the non-conflicting Outcome 2 plan/boundaries, all exact production owners, workflow, both schemas/registration, Jobs A–E, thin integration, portable/focused tests, and every tracked Outcome 2 fixture
- **Method:** static and portable only. No `--workflow-bound` selector, sudo, native primitive, workflow event, network acquisition, provider, cloud, AWS, OpenTofu, deployment, or production action was run.
- **Verdict:** **BLOCKED — no ADR 0092 signoff**

## Severity summary

| Severity | Count | Disposition |
| --- | ---: | --- |
| P0 | 0 | none found |
| P1 | 4 | unresolved; blocking |
| P2 | 1 | unresolved; blocking |
| P3 | 0 | none separate from the findings below |

## Findings

### P1-1 — The launcher CLI converts successful completion to failure

**Requirement:** ADR 0092 section 3: every CLI wrapper must catch `Exception`, not `BaseException`, or raise `SystemExit` outside the protected body so success remains exit zero.

`deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:3492-3500` does the prohibited opposite:

```python
try:
    raise SystemExit(_bootstrap_main())
...
except BaseException:
    ...
    raise SystemExit(1)
```

If `_bootstrap_main()` returns zero, `SystemExit(0)` is caught by the `BaseException` handler and replaced with exit one. The held-client and root string bootstraps currently raise their own `SystemExit` outside this block, so this does not forge a pass; it still leaves the tracked production CLI semantically broken and directly violates the accepted correction. The six clients and common corrected this pattern, but the launcher wrapper did not.

### P1-2 — Report-custodian startup still loses descriptor ownership on required cuts

**Requirement:** ADR 0092 section 4: preregister the surviving custodian behind a release gate, retain pidfd/process authority through authenticated retirement, and aggregate every startup/close/failure cut to exact retained state or baseline restoration.

`_start_custodian()` detaches and registers both socketpair descriptors at `scripts/native-qualification/common.py:805-807`, then calls `os.urandom()` and `os.fork()` at `:808-809` outside any recovery block. Either failure leaks the detached descriptors because `NativeSession.begin()` has no owner to close when `_start_custodian()` itself raises.

Parent startup recovery is also incomplete. At `:817-833`, failures in `pidfd_open`, child-end close, release send, or readiness receive do not close the registry's control/child leases. If `pidfd` exists, `_retire_child()` always raises its `ExceptionGroup` at `:803`, so control never reaches any later cleanup. If it does not exist, the child is killed/reaped but both registered socket leases remain open. The child process is gated, which is positive, but the parent does not restore its fd baseline on these mandatory cuts.

The focused common test substitutes `Cust` for this path and only token-checks custodian symbols. It has no `socketpair`/random/fork/pidfd/release/read/close startup fault corpus. This is both a production ownership defect and a missing required acceptance oracle.

### P1-3 — B/integration can lose exact authority over the blocked tool child at secondary pidfd registration

**Requirements:** ADR 0092 sections 3, 4, and 9: stable process ownership, all process/pidfd/release cuts, and exact baseline restoration.

The namespace owner atomically spawns and locally owns the gzip/zstd child, then reports only its PID. The outer ordinary/compression coordinator receives that PID and calls `_ProcessOwner.register(child["pid"], waitable=False)` at `completion_trusted_runtime_launcher.py:1747-1749`. `register()` appends a lease and only afterward calls `os.pidfd_open()` at `:748-751`.

If that `pidfd_open` fails, outer cleanup owns a nonzero PID lease with no pidfd and therefore refuses to signal or reap it as exact authority. Killing the namespace leader closes the unreleased gate, so the child may exit, but it can be adopted as an unreaped descendant and the outer owner still cannot prove exact siginfo/wait/reap. This cut necessarily becomes cleanup uncertainty rather than the required exact retained transaction or restored process baseline.

No portable row selects this secondary `pidfd_open` cut through complete `_run_tool_with_ops`. The new outer corpus covers `_ProcessOwner.spawn()`/`clone_pidfd` for the held Python client, not this post-status registration in the B/integration tool transaction.

### P1-4 — Mandatory production-path acceptance is still incomplete and one new ledger accepts unrelated early failures

**Requirement:** ADR 0092 section 9 requires adapters to invoke the complete production state machine above mocked native syscalls and equality of declared, selected, consumed, and oracle-proved cases for every listed domain.

The checked-in gates do not meet that contract:

- `test/outcome-two-trusted-launcher-portable.py:536-585` routes the original launcher rows directly to `_enter_boundary`, `_descriptor_snapshot`, `_RootOwner.prepare`, `_materialize_root`, and issuance helpers. Those are useful unit tests, but they do not run the complete admitted E, D, ordinary, compression, or publication transactions.
- There is no portable invocation of complete `_qualify_admitted_fixed_process_lifecycle()` for the three D transactions, complete `_sandbox_only_transaction()` for E, or complete report-custodian startup/publication/upload-loss/retirement recovery.
- `test/outcome-two-lifecycle-portable.py` exercises closure helper lifecycle and isolated `_ProcessOwner` methods; it does not execute the D owner. `test/outcome-two-recovery-portable.py` fabricates owner state and calls recovery helpers rather than cutting the complete authority-bearing transaction.
- The new held-process corpus at `test/outcome-two-trusted-launcher-portable.py:1094-1120` adds every row to `consumed` and `oracle` whenever any listed exception escapes. It never requires `ops.fired` for a rejecting row and never compares the observed typed code with `intended_code`. An unrelated earlier rejection therefore satisfies declared/selected/consumed/oracle equality without consuming the row's named syscall fault.
- The workflow companion parses blocks with indentation/string regexes, but lines `338-390` never assert the A–E `needs` edges, never simulate the parsed dependency graph, and prove “no native selected” only by directly calling common's eligibility branch. Removing an eligibility dependency from a native job would leave that sentinel green.

C now has a substantial direct owner corpus and the root capsule has a self-consistent unauthorized-byte rejection check. Those corrections do not satisfy the omitted D, E, custodian, tool-child, workflow-dispatch, and all-cut matrices. Green portable output is consequently non-accepting for ADR 0092 section 9.

### P2-1 — Readable-transition policy is violated and the required all-surface static gate does not exist

**Requirement:** ADR 0092 section 8 forbids packing multiple fallible effects or claim derivations on one physical line and requires AST/static checks for closure, launcher, common, and all six clients.

The launcher contains 79 lines over 160 columns. Security result construction at `completion_trusted_runtime_launcher.py:1808` is one **1,804-character** physical line deriving the complete tool claim mapping. The cleanup claim mapping at `:1944` is 580 characters, and several security transitions use same-line `try`, `except`, or raise bodies. This is the exact claim-compression the ADR forbids, not merely style.

The tests do not enforce the accepted scope. `test/native-qualification-common.test.ts:393-407` checks width/AST only for `common.py`. `test/outcome-two-portable.test.ts` bans semicolons but has no fallible-effect/claim-derivation AST rule for closure, launcher, or the six clients. Launcher is already exactly `3500 / 3500`, so expansion cannot be hidden beyond the individual high; it requires readable restructuring/deletion within the accepted accounting or a new measured ADR.

## Six real production paths traced

All workflow jobs check out `${{ github.event.pull_request.head.sha }}`, run from a clean same-repository attempt-one envelope, and pass a fixed environment into the tracked client. Common then holds the four source generations plus the exact client, authenticates Git blob identities at the fixed head before compiling the held launcher, invokes one typed operation, freezes an operation receipt, observes common baselines, derives report checks/metadata, hands canonical bytes to the custodian, uploads, and invokes authenticated cleanup. The required-final job names every job/upload/cleanup outcome.

| Path | Exact call chain and boundary | Static disposition |
| --- | --- | --- |
| **A** | workflow A → `NativeSession.run_fixed_operation("A")` → held-source admission → `invoke_fixed_admitted_operation` → sealed held Python → `_bootstrap_with_ops` mapping mode → closure `_qualify_fixed_python_mapping_with_ops` → real resolver/helper/maps owner → A independent normalization → common receipt/report | Production and metadata relationships are closed; portable mapping coverage passes. Blocked only by shared CLI/custodian/readability/acceptance gate. |
| **B** | workflow B → operation `B`/compression mode → `_coordinate_with_ops` → trusted closure issuance → gzip then zstd `_run_tool_with_ops` → parser/tool/aggregate result → B recomputation → common report | Mask 63, both marker digests, parser closure, per-tool closures/mappings, and aggregate closure are bound. Blocked by P1-3 and shared findings. |
| **C** | workflow C → descriptor mode → closure `_qualify_fixed_descriptor_primitives_with_ops` → strict bounded getdents → fixed-Python exec inheritance → exact waitid/waitpid/reap → close-range/limit/fd/process settlement → C decoder/common report | The production transaction and new direct C corpus materially satisfy section 6; close-range uncertainty fails closed. Shared findings still block signoff. |
| **D** | workflow D → lifecycle mode → `_qualify_admitted_fixed_process_lifecycle` → independent before-release, after-release, TERM/KILL `_run_lifecycle_case` calls → second setsid gate → credentialed pidfd transfer/EOF → identity-edge census/adoption → exact signal reap → subreaper/fd/process restoration → D decoder/common report | Production structure matches section 6. No complete D production-path fault matrix exists, so the claims are not acceptably oracle-proved. |
| **E** | workflow E → sandbox mode → fixed root authority/capsule → fixed sudo command → root authority check before held-launcher compilation → `_root_capsule_entry` → `_sandbox_only_transaction` → registered leader and transferred inner pidfd → post-entry namespace/mount/path readback → exact cleanup → fixed policy digest/common report | Root self-consistent unauthorized generations reject and E observes after entry. Native sudo policy/command pin is intentionally deferred. Complete E/all-cut portable acceptance is missing. |
| **Integration** | workflow integration, gated on A–E → runtime mode → same closure issuance and two real tool transactions as B → exact ordinary result → thin client's closure/source/two-marker binding → common receipt/report | Thin composition is real and metadata is closed. Blocked by P1-3 and shared acceptance/custodian findings. |

## ADR 0092 requirement matrix

| ADR 0092 requirement | Result at `3846383` |
| --- | --- |
| **1. Independently pinned root authority before sudo** | **Static implementation present.** Rendered bootstrap embeds revision, launcher/source-set digests, and ordered source rows; self-consistent unauthorized rows reject before compile. No sudo execution authority or policy pin exists or was consumed. |
| **2. Held source admission before tracked launcher/client execution** | **PASS static.** Common holds/authenticates the four sources and exact client against the head before compiling held launcher bytes; no admitted route reopens those tracked source/client paths. |
| **3. Operation-bound common, immutable receipts, stable baselines, CLI exits** | **FAIL.** Operation/cleanup receipts and stable observations are present, but P1-1 violates the exact CLI rule. |
| **4. Durable generation custodian and exact recovery** | **FAIL.** Durable intent/exchange classification is materially improved, but P1-2 leaves mandatory startup descriptor cuts outside aggregate ownership and their required corpus is absent. |
| **5. Exact A/B/E/integration metadata semantics** | **PASS static.** A cross-role digest rejection and summaries, B parser/aggregate and mask 63, E fixed policy digest, and integration closure/source/two fixed outputs are independently checked by common/client/schema layers. |
| **6. Separate C and D real transactions** | **Production present; acceptance FAIL.** C directly executes the intended transaction. D has three separate transactions and aggregate restoration, but lacks the required complete production-path portable oracle. |
| **7. E post-entry observation and registered inner ownership** | **PASS static production; acceptance incomplete.** The inner pidfd is transferred/registered before release and readback occurs after entry. No complete E cut matrix executes it. |
| **8. Exact-head workflow and readable control flow** | **FAIL.** Exact-head checkout/final wiring is present; P2-1 violates readable claim transitions and the workflow dispatch oracle is incomplete. |
| **9. Production-path portable acceptance and equal case sets** | **FAIL.** P1-4 and P1-2/P1-3 name omitted or non-oracle-proved required domains. |
| **10. Five clean reviews before any execution** | **FAIL at holistic gate.** This fresh review has unresolved P1/P2. Native execution remains forbidden and was not attempted. |

## Outcome 2 completion boundary

This review supplies no native authority. Jobs A–E and thin integration have not run on this head, so Outcome 2's native completion conditions, exact runtime objects on hosted Linux, real namespaces/seccomp/mounts, report artifacts, and same-run integration remain unproved. Phase B, AWS, provider, OpenTofu, deployment, production, release, and issue closure remain outside authority.

## Accounting

Gross additions from `bec0a19` are within every ADR 0092 numeric high:

- trusted/portable: **11,167 / 14,500**;
- native: **4,308 / 7,500**;
- listed aggregate: **15,475 / 22,000**;
- closure **2,647 / 2,650**; launcher **3,500 / 3,500**; common **1,250 / 1,250**; workflow **317 / 350**; native schema **331 / 550**; fixtures **392 / 1,200**; all other listed files are within their individual highs.

Numeric compliance does not waive P2-1; unused aggregate margin is not transferable to the exhausted launcher file.

## Verification

- Seven isolated `/usr/bin/python3 -I -B` Outcome 2 portable suites: **PASS**.
- Seven optimized `-O -I -B` rejection runs: **PASS**.
- `py_compile` for parser, closure, launcher, common, A–E, and integration: **PASS**.
- Python AST parse for closure, launcher, common, A–E, and integration: **PASS**.
- `git diff --check c18b7f5..3846383` and `git diff --check 3846383^..3846383`: **PASS**.
- `git fsck --no-progress --no-dangling`: **PASS**.
- Focused TypeScript/AJV/full `npm` gates: **not run** because this checkout has no `node_modules`; no dependency installation or network access was attempted.
- Native, privileged, workflow, provider, cloud, and AWS actions: **not run**.

# SIGNOFF: BLOCKED

`3846383f0d88c190226356ca9aeeeda402943aaa` has four unresolved P1 findings and one unresolved P2 finding. Do not authorize `--workflow-bound`, sudo/native execution, workflow dispatch/rerun, artifact reliance, production, release, issue closure, provider/cloud/AWS/OpenTofu/deployment activity, or an Outcome 2 completion claim.
