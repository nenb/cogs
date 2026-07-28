# Outcome 2 native final hostile review — A/B and launcher reachability

- Review ID: `O2-NATIVE-FINAL-AB`
- Exact implementation head reviewed: `ea6e74fe709e02061e13be78922da13a8cf6f748`
- Governing decisions: accepted ADR 0087–0090, including the later private bootstrap/issuer execution contract where it supersedes ADR 0087's original public handoff
- Scope: trusted launcher/closure reachability, fixed admitted modes, Job A, Job B, native common/schema and focused portable/static companions
- Method: fresh source/AST/schema/control-flow review plus portable modeled tests only
- Native execution: **not performed**. No workflow-bound driver, native selector, `map_files`, compression executable, namespace, mount, seccomp, sudo, cloud, provider, or deployment route was invoked.
- Verdict: **BLOCKED**

## Findings

### P1-1 — Job B rewrites the observed full execution-seal mask into a weaker false report value

**Exact symbols:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:38-39,550-560` — `_EXEC_SEALS` and `_runtime_metadata`
- `scripts/native-qualification/job-b-compression.py:278-295` — `qualify`
- `schemas/native-qualification-report-v1alpha1.json:142-154` — `BTool`
- `test/native-qualification-b.test.ts:51-69` — portable oracle

Production reports the required six-bit execution profile as `_EXEC_SEALS == 63` (`SEAL|SHRINK|GROW|WRITE|FUTURE_WRITE|EXEC`). Job B correctly requires incoming `seal_mask == 63`, but then copies the row and deliberately changes `seal_mask` to `15`. The schema fixes the published value to 15, and the portable test explicitly requires that conversion.

The uploaded native report therefore does not contain the actual observed seal mask and omits `F_SEAL_FUTURE_WRITE` and `F_SEAL_EXEC` from its claimed metadata. This directly violates ADR 0090's requirement that B bind the exact seal mask and makes an apparently valid pass report materially false.

A portable diagnostic confirmed the transformation `63 -> 15` through the real `qualify` function.

### P1-2 — The A/B outer launch transaction can leak descriptors or an unreaped child at ordinary failure cuts

**Exact symbols:**

- `scripts/native-qualification/job-a-runtime-mappings.py:180-217` — `_launch`
- `scripts/native-qualification/job-b-compression.py:214-251` — `_launch`
- corresponding `_wait` implementations at A `:144-178` and B `:177-211`

Both drivers allocate four pipe pairs and a source-root fd, then fork, before entering an ownership/recovery transaction. None of those descriptors is placed in a one-shot lease/registry before the next fallible allocation. After fork, the parent performs a sequence of raw closes before a cleanup guard. A close failure can escape while the gated child is live.

If admission or release writing fails, `finally` closes only the two write gates and pidfd; it neither boundedly terminates/reaps the child nor closes the output/error descriptors. The pidfd-acquisition failure path waits for the child but, if its deadline assertion fires, does not terminate it and does not reach descriptor cleanup. The normal owner also records no start-time/session/process-group/executable identity before release.

This fails ADR 0087/0089/0090 preregistration, retained process authority, bounded reap, and aggregate cleanup rules. A disposable runner cannot supply the missing evidence.

### P1-3 — Common report cleanup deletes names after replacement/identity failure instead of preserving foreign state

**Exact symbols:**

- `scripts/native-qualification/common.py:252-281` — `_remove_owned`
- `scripts/native-qualification/common.py:343-367` — failed-publication cleanup
- `scripts/native-qualification/common.py:368-391` — `cleanup_report`

`cleanup_report` correctly detects validation or generation mismatch, but it appends that error and unconditionally calls `_remove_owned`. `_remove_owned` blindly unlinks both `.report.tmp` and `report.json` by retained-directory name without comparing each name to the generation owned by the transaction. The failed-publication route does the same.

Consequently a staged/final replacement can be classified as foreign and then still be deleted. That violates the exact-owned-state cleanup contract: replacement must be terminal uncertainty and cleanup may remove only the retained authenticated generation. The focused common test checks the happy path and source tokens; it does not exercise replacement, close-after-effect, or identity-bound no-delete behavior.

### P1-4 — End-to-end Job A is not mapping-only and its portable proof substitutes a fabricated closure owner

**Exact symbols:**

- `scripts/native-qualification/job-a-runtime-mappings.py:122-140` — `_child`
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1576-1616` — `_coordinate_admitted_mapping_only`
- `test/outcome-two-trusted-launcher-portable.py:581-685` — `mapping_only_coordinator`

The admitted production coordinator itself is statically narrow: it resolves fixed `/usr/bin/python3`, uses the real closure resolver/helper/`map_files` methods, binds executable/loader/library roles, and restores closure-local fd/child baselines. However, the real Job A wrapper first executes `unshare(CLONE_NEWUSER|CLONE_NEWNS)`, writes UID/GID maps, makes mounts private, and bind-mounts a private root onto `/run`. The mapping coordinator never uses that `/run` mount. Job A therefore depends on and mutates unrelated namespace/mount primitives instead of qualifying only the mapping primitive assigned to A.

The portable coordinator test does not close this gap. It constructs a synthetic module and replaces `_resolve_tool`, `_spawn_helper`, `_mapped_closure`, `_stop_helper`, source close, fd snapshots, and child snapshots with completed mocks. Its fabricated resolved closure contains only one executable and no loader, yet the test accepts the coordinator result. The separate Job A oracle supplies a hand-built loader row, so no portable path drives the admitted bootstrap through the actual closure loader-role predicate.

This is the substitutable-completed-owner pattern ADR 0088/0089/0090 prohibit, and it leaves both fixed-mode authenticity and the A mapping/loader production composition unproved before native execution.

### P2-1 — Job B accepts any equal pair of output digests instead of the exact deterministic output

**Exact symbol:** `scripts/native-qualification/job-b-compression.py:262-296`, `qualify`.

B binds each tool row to its top-level output digest and requires gzip and zstd to be equal, but never compares either digest to SHA-256 of the fixed expected bytes `b"cogs-runtime-qualification-v1\n"`. Two identical wrong outputs therefore pass the Job B oracle and schema.

A portable diagnostic changed both top-level and tool output digests to the same arbitrary 64-hex value; the real `qualify` function accepted both rows. This does not establish the required exact deterministic decompression result.

### P2-2 — Fixed mapping/compression mode routing is asserted structurally, not exercised through the production bootstrap

**Exact symbols:**

- `completion_trusted_runtime_launcher.py:11,1836-1879` — `_ADMISSION_MODES` and `_bootstrap_with_ops`
- `test/outcome-two-trusted-launcher-portable.py:687-703,755-780` — `fixed_bootstrap_modes` and final source-text checks

The production bootstrap has one fixed fd ABI and statically authenticates the held launcher/parser/closure/schema bytes before routing. The ordinary `cogs.runtime-source-admission/v1` result also remains the exact frozen `RuntimeQualificationResult`; compression metadata is added only in compression mode, and no private path/fd/source-generation field is emitted. Those are positive properties.

But portable mode coverage only compares the `_ADMISSION_MODES` dictionary and searches source text. Bootstrap fixture execution uses the ordinary admission version; mapping is called directly with a fabricated closure module; compression metadata is called directly with fabricated rows. No portable test drives authenticated fd-3 admission through `_bootstrap_with_ops` for mapping and compression, rejects cross-mode output substitution, or proves that a mode cannot alter the ordinary result. Given P1-4's completed mocks, fixed admitted-mode authenticity is not an accepting gate.

## Requested contract disposition

| Contract area | Disposition |
| --- | --- |
| Exact head | **PASS** — review started and ended at `ea6e74fe709e02061e13be78922da13a8cf6f748` |
| Production bootstrap/API static reachability | **PASS, non-accepting overall** — A/B reach the zero-argument launcher executable through fixed fds 3/4; the superseding private bootstrap contract, not ADR 0087's deleted forgeable public handoff, is present |
| Fixed admitted mode authenticity | **BLOCKED** by P1-4/P2-2 |
| A mapping-only production coordinator and loader role | **Coordinator statically present; end-to-end qualification BLOCKED** by P1-4 |
| B actual source/seals/execution metadata | **BLOCKED** by false seal publication in P1-1; source/sealed bytes and final mapping digests are otherwise statically bound in `_runtime_metadata` |
| Ordinary runtime-result exactness | **PASS statically** — frozen closed dataclass, no dynamic compression/mapping metadata |
| Exact deterministic B result | **BLOCKED** by P2-1 |
| No private path/fd/source-generation disclosure | **PASS statically** for ordinary, A, B, and native report schemas |
| Preregistration and exact cleanup | **BLOCKED** by P1-2/P1-3 |
| No substitutable completed mocks | **BLOCKED** by P1-4 |

## Portable/static verification

- Seven direct isolated Outcome 2 Python portable suites: **PASS**.
- Trusted-launcher portable suite: **PASS**, but non-accepting under P1-4/P2-2.
- AST parse of launcher, closure, ELF, common, A, B, and launcher portable suite: **PASS**.
- Focused B metadata diagnostic: **FAIL contract** — observed mask 63 published as 15.
- Focused B exact-output diagnostic: **FAIL contract** — arbitrary equal output digests accepted.
- Native gross-addition subtotal from `bec0a19`: **3811/4000**, within ADR 0090's binding subtotal; reviewed individual surfaces are within their highs.
- `git diff --check fccef15..ea6e74f`: **PASS**.
- `git fsck --no-progress --no-dangling`: **PASS**.
- TypeScript/AJV companions: **not run** because locked `node_modules/.bin/tsx` is absent.
- Native selectors and privileged/cloud operations: **not run**.

## Signoff

**BLOCKED.** Exact head `ea6e74f` has four unresolved P1 findings and two unresolved P2 findings. Do not authorize Jobs A/B, rely on their artifacts, run thin integration, or grant production/issue-closure authority from this head.
