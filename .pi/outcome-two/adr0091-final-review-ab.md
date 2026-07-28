# ADR 0091 final hostile review — production API and Jobs A/B

- **Reviewed implementation head:** `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08`
- **Scope:** production closure/launcher operation API, held-byte admission, Jobs A/B, native common/report/schema, and focused/portable companions
- **Method:** fresh static/source review plus portable modeled tests only
- **Native/cloud execution:** **not performed**. No `--workflow-bound` selector, sudo, namespace, mount, seccomp, `map_files`, compression executable, native workflow, provider, cloud, or AWS operation was invoked.
- **Verdict:** **BLOCKED**

## P0

No P0 finding.

## P1 findings

### P1-1 — The outer production client executes unauthenticated checkout launcher bytes before source admission, then reopens a different launcher generation

`SystemCommonOps._launcher()` opens the checkout launcher and immediately `compile`/`exec`s its bytes (`scripts/native-qualification/common.py:197-208`). Only code from that already-executing module later reaches `_prepare_held_client()`, which reopens the fixed source paths via `_held_sources()` and performs Git-tree authentication (`completion_trusted_runtime_launcher.py:2016-2032`). Thus authentication is performed by code whose own generation was never bound to the admitted revision before execution.

The second `_held_sources()` read also means the generation executed by the inner fd-3 bootstrap is not the retained generation from common's outer read. This violates ADR 0091's requirement that A/B execute held admitted launcher bytes without reopening a launcher pathname after the outer source read. A mutation between the common read and `_prepare_held_client()` either obtains pre-admission execution in the parent or changes which generation is transported inward.

The inner bootstrap itself does authenticate its reopened source set and driver before entering the fixed owner, but that does not retroactively authorize the outer code that selected and launched it.

### P1-2 — Outer process/fd ownership is not closed at release/transition and custodian cuts

The held-client path has a real `_ProcessOwner`, but its transition recovery is incomplete. `_ProcessOwner.release()` writes the release byte, records `released`, and then closes the gate (`launcher.py:742-747`). The child performs `setsid()` before sending the transition byte (`:1838-1842`), while the parent does not update the registered session/group until `confirm_setsid()` (`:1859-1862`). A release-gate close error, transition-read error/after-effect error, or identity-read error after the child's `setsid()` enters cleanup with the preregistered pre-transition session/group. `_stop_process()` then requires `_process_matches()` before TERM/KILL (`:892-922`) and can refuse to signal the live blocked child because the planned transition occurred but was never committed. The required recovery authority is therefore race-dependent at named fault cuts.

The report custodian has an independent ownership hole. `_start_custodian()` uses raw `socketpair`/`fork`; the child starts effects before the parent obtains a pidfd (`common.py:507-526`). A fork-parent/pidfd/START/read failure can leave the child live without bounded termination/reap. After publication, `_CustodianClient.publish()` closes the only parent pidfd before upload (`:497-505`); post-upload cleanup reconnects by abstract socket and never waits for or proves custodian exit (`:638-668`). The report lease can therefore appear retired while its process owner remains unproved.

These are exactly the outer pipe/fork/pidfd/write/read/close cuts ADR 0091 requires to be leased and recoverable before the next effect.

### P1-3 — Job B drops the aggregate trusted-closure binding from the uploaded artifact

The production result correctly carries `closure_sha256`, and Job B checks that it equals the ordinary runtime result (`job-b-compression.py:109-140`). However `qualify()` returns only the two tool rows (`:180`), `NativeSession.publish()` stores only those rows, and the schema fixes B metadata to exactly two `BTool` objects. `common._validate_semantics()` consequently recomputes only each gzip/zstd tool closure (`common.py:447-459`).

The aggregate production closure digest includes the parser closure as well as zstd and gzip. Neither that digest nor the parser rows needed to recompute it survive into the B report. An independent artifact consumer therefore cannot bind the uploaded evidence to the complete closure that production issued and executed. This fails the full-closure and independent top-level-summary requirement even though the in-process producer value was correct.

The reviewed code does correctly retain seal mask `63`, bind source/sealed executable digest and size, require full per-tool object vectors, require execution mapping equality, and bind both outputs to `6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8`. Those positives do not restore the missing aggregate closure authority.

### P1-4 — Mandatory production fault acceptance is still replaced by completed adapters, utility probes, and source sentinels

The portable suites do not drive the required owner paths at all named cuts:

- `common_production_adapters()` replaces `_run_held_python_with_ops` with `held_execution()`, which directly fabricates completed typed results (`test/outcome-two-trusted-launcher-portable.py:705-842`). It does not execute the production held-client process owner.
- The trusted-launcher fixture has only eight rows, none targeting `_run_held_python_with_ops`, `_prepare_held_client`, `invoke_fixed_mapping_qualification`, or `invoke_fixed_compression_qualification`. It therefore omits the required open/memfd/pipe/clone-pidfd/release/admission/transition/exec/output/error/EOF/reap/close matrix.
- The A owner companion checks source tokens for `_resolve_tool`, `_spawn_helper`, `_mapped_closure`, and `_stop_helper`; it does not execute `_qualify_fixed_python_mapping_with_ops` through resolution, helper, maps, cleanup, and result construction cuts (`test/outcome-two-mapped-closure-portable.py:249-276`).
- Focused A/B tests exercise the report normalizers using hand-built completed mappings/runtime results and stop their common adapter before the owner. They prove metadata predicates, not production-owner reachability.
- The common companion drives one synthetic `NativeSession` happy path and isolated `_write_all`, `_read_all`, lease, dirent, and `_name_matches` helpers. It never executes `_start_custodian`, `_custodian_main`, `cleanup_report`, worker crash, upload failure, publication collision, fsync uncertainty, replacement, or custodian-loss recovery. Several assertions are token searches (`test/native-qualification-common.test.ts:150-209`).

Accordingly AT91-BOOT-01, AT91-OUTER-01, AT91-REPORT-01, and the branch-removal/declared-selected-consumed-oracle requirement are not accepting gates. The defects in P1-1/P1-2 are examples of cuts the green modeled suites never select.

## P2 findings

### P2-1 — Report cleanup still has a check-then-unlink replacement window

The custodian retains the report descriptor, but cleanup calls `_name_matches()` and then performs a separate pathname `os.unlink()` (`common.py:603-612`). A same-UID replacement between those operations is deleted even though it is not the retained generation. The same pattern exists in the exception cleanup loop (`:623-631`). ADR 0091 requires a mismatch/replacement to be preserved and forbids destructive selection from pathname state alone. No focused test schedules replacement between the identity check and unlink.

## P3 findings

### P3-1 — The readable-authority gate is absent and common reaches its line high by packing fallible transitions

`common.py` is exactly `750/750` gross lines and repeatedly combines authority transitions on one physical line. For example `FdRegistry.open()` performs the fallible allocation and later adoption in one expression (`:117-119`), so an adoption rejection can leak the newly returned fd; numerous cleanup/state decisions are similarly semicolon-packed. The common companion checks only a 160-character width ceiling, not ADR 0091's AST/static rule that each fallible effect have an immediately visible lease/registration transition and that packed multi-effect lines reject.

## Verified positive properties

- Jobs A/B are thin fixed-operation clients and contain no local namespace, mount, fork, pipe, wait, or cleanup-claim implementation.
- The admitted inner dispatch binds the exact operation/client/revision/source-set, rejects replay and cross-profile result types, and reaches the closure mapping entry or launcher compression entry.
- A's producer, driver, common semantics, and schema enforce executable/loader/library order, 128 MiB bounds, unique ordered `needed`, provider closure, mapped role/digest sequence, and independently recomputed closure/mapping summaries.
- B's production and report layers retain mask `63`, exact fixed-output digest, source/sealed equality, complete per-tool object vectors, and per-tool closure/mapping recomputation.
- Relevant gross additions are within ADR 0091 highs: trusted/portable `9308/10790`, native `3329/5400`, aggregate `12637/16250`; launcher and common are exactly at their individual highs (`2600/2600`, `750/750`).

## Portable/static verification

- Exact head before review: **PASS** — `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08`.
- Python compile/AST for closure, launcher, common, A, and B: **PASS**.
- `test/outcome-two-mapped-closure-portable.py`: **PASS, non-accepting under P1-4**.
- `test/outcome-two-trusted-launcher-portable.py`: **PASS, non-accepting under P1-4**.
- `test/outcome-two-lifecycle-portable.py`: **PASS, non-accepting for the held-client/report outer cuts**.
- `test/outcome-two-recovery-portable.py`: **PASS, non-accepting for the held-client/report outer cuts**.
- `git diff --check a3f529a^..a3f529a`: **PASS**.
- `git fsck --no-progress --no-dangling`: **PASS**.
- TypeScript/AJV focused suites: **not run** because locked `node_modules/.bin/tsx` is absent; no dependency or network acquisition was attempted.
- Native selectors, privileged primitives, provider/cloud/AWS operations: **not run**.

## Signoff

**BLOCKED.** Exact implementation head `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08` has unresolved P1, P2, and P3 findings. It does not qualify for ADR 0091 signoff, native execution authority, artifact reliance, production closure, release, issue closure, or any cloud/AWS action.
