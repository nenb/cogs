# Outcome 2 Wave 1 — candidate branch decomposition

**Role:** Outcome 2 Wave 1 Agent 1  
**Audit date:** 2026-07-27  
**Clean audit head:** `908041cf6473c10667a030c11c6798cb2338c5d4` (`research/outcome2-decompose`)  
**Clean head parent / candidate merge base:** `8caab23bb4277121a77d80dc043b3c2c43b07ced`  
**Candidate ref and audited tip:** `feat/issue42-candidate-tar-remediation` at `d96b58ab55e932dda8b1cc007b7f88ad483f336e`  
**Candidate remote tip:** `origin/feat/issue42-candidate-tar-remediation` at the same SHA  
**Candidate-only reachable commits:** 119 (89 first-parent, 30 merged documentation-side commits)  
**Clean-head-only commit:** `908041cf6473c10667a030c11c6798cb2338c5d4` (`OUTCOME-TWO-PLAN.md` only)

## 1. Decision

Freeze the candidate branch. Do **not** merge it, rebase it, or cherry-pick its tip.

Decompose it as follows:

| Action | Count | Exact treatment |
|---|---:|---|
| **KEEP-O1** | 17 commits | Preserve the first-parent range ending at `de027e33312be49e5b825c0abc7e864688ae2aaa` as the Outcome 1 atomic-rootfs PR. |
| **SPLIT-O2** | 1 commit | Do not cherry-pick `a7914db60cd5ed3a76c081299ab1b79c56455b21`; extract only the named trusted runtime-closure/process concepts into new, dedicated Outcome 2 commits after the Wave 1 architecture gate. |
| **DROP** | 101 commits | Omit from clean PR history. This includes duplicate ADR-side commits, ADR 0065–0086 planning/corrections, the guarded Phase B discovery attempt and revert, and all native-preflight workflow/diagnostic iterations. Preserve them only on the frozen research ref. |

This keeps the proven Outcome 1 tree intact, avoids importing the monolithic native sandbox, and retains a small amount of production-grade Outcome 2 source as reviewable extraction material.

## 2. Authority and accepted-ADR interpretation

I read `OUTCOME-TWO-PLAN.md`, `COGS.md`, `DESIGN.md`, `IMPLEMENTATION.md`, `SECRET-INJECTION.md`, accepted ADRs 0038–0056 on the clean head, and candidate ADRs 0057–0086.

The relevant constraints are:

- ADRs 0038–0056 establish the fixed Stage 2 inputs, direct one-writer/one-walker rootfs route, exact cleanup, candidate/authority separation, and local/cloud stops.
- Candidate ADRs 0057–0064 narrowly authorize and harden the atomic anonymous candidate-tar remediation. Those decisions belong with Outcome 1.
- Candidate ADR 0065 records successful hosted rootfs qualification at exact source `de027e33312be49e5b825c0abc7e864688ae2aaa`, but its implementation authority starts Phase B. The Outcome 1 code/evidence cut is therefore the **parent** of the integrated ADR 0065 commit: `de027e33312be49e5b825c0abc7e864688ae2aaa`.
- ADRs 0065–0070 are Phase B/runtime-discovery planning and correction history. ADRs 0071–0086 are the native-preflight experiment and repeated hosted-environment corrections.
- `OUTCOME-TWO-PLAN.md` now explicitly freezes this branch, preserves Outcome 1, treats later native-preflight work as research, moves host discovery to a trusted preparation phase, and requires a new Wave 1 architecture decision before implementation.

Accepted ADRs 0065–0086 should not be erased or rewritten. They remain historical on the frozen branch. The new architecture ADR should explicitly supersede their Phase B/native-preflight mechanisms where they conflict with the trusted-preparation design; they should not be copied into clean implementation PRs merely because they were accepted under the old plan.

## 3. Outcome 1 exact keep map

### 3.1 Exact commit sequence

These 17 first-parent commits are the complete Outcome 1 keep set, in application order:

1. `c25c851063ed654adf3bf1162004b8e8b513b7ef`
2. `5522a53529d7a2a40a444f42c0f98fb472f68572`
3. `f43b864306b02d3e87057440f4579dcd9cd08b6b`
4. `8663d652fabc909e3f29f9bda898c54fedfd9fd3`
5. `bf598260752eecd0f9321d90dd33230fab60382c`
6. `f40588eae988eb3236bdf654d8db32158621c96f`
7. `b95fdb917e0dd580b8ef2cb0f2f30cec503435f3`
8. `65ff8e4568eb882c28add0e9f174722e7698880a`
9. `6feccbe72589afdf3790dfc755a92bba9ccf071d`
10. `e1da5af575ef3cfa4eaf9319b36144ff6ce7fd07`
11. `bc4d3673ef13538e5af987badcc027c572aa9e70`
12. `4fcfad33dcd2152e23ac00595faec7ddc0cd6356`
13. `14fbda9f77506ba2140bd6b38913f96ae9535705`
14. `35c4f922889e56c33def5e429604afd8ae4ad53b`
15. `79665f53f9c7ec1652d42d6c004159ad52b37b45`
16. `cb5b6e2f48af9d05769c75b1a1963506e220b906`
17. `de027e33312be49e5b825c0abc7e864688ae2aaa`

They are a linear first-parent series from `8caab23bb4277121a77d80dc043b3c2c43b07ced`. Do not substitute the similarly titled documentation-side SHAs; those later enter the candidate graph through merges and are duplicates for decomposition purposes.

### 3.2 Exact Outcome 1 file map

Keep the exact blobs at `de027e33312be49e5b825c0abc7e864688ae2aaa` for these paths:

**Production**

- `deploy/aws-feasibility/remote/completion_rootfs_build.py`
- `deploy/aws-feasibility/remote/completion_rootfs_builder.py`
- `deploy/aws-feasibility/remote/completion_rootfs_candidate.py`
- `deploy/aws-feasibility/remote/completion_rootfs_fs.py`
- `deploy/aws-feasibility/remote/completion_rootfs_ledger.py`
- `deploy/aws-feasibility/remote/completion_rootfs_publish.py`

**Outcome 1 qualification**

- `.github/workflows/stage2-rootfs-full-build-qualification.yml`
- `test/aws-stage2-completion-rootfs-builder.py`
- `test/aws-stage2-completion-rootfs-candidate.py`
- `test/aws-stage2-completion-rootfs-candidate.test.ts`
- `test/aws-stage2-completion-rootfs-canonical.py`
- `test/aws-stage2-completion-rootfs-fs.py`
- `test/aws-stage2-completion-rootfs-fs.test.ts`
- `test/aws-stage2-completion-rootfs-ledger.py`
- `test/aws-stage2-completion-rootfs-publication.py`

**Outcome 1 decisions**

- `docs/adr/0057-authorize-atomic-candidate-tar-remediation.md`
- `docs/adr/0058-authorize-atomic-candidate-test-companions.md`
- `docs/adr/0059-authorize-filesystem-typescript-companion.md`
- `docs/adr/0060-raise-hosted-driver-cap-after-final-review.md`
- `docs/adr/0061-raise-hosted-failure-path-cap.md`
- `docs/adr/0062-raise-signal-safe-hosted-driver-cap.md`
- `docs/adr/0063-raise-supervisor-candidate-cap.md`
- `docs/adr/0064-authorize-no-bytecode-replacement-run.md`
- only the ADR 0057–0064 rows/history additions in `docs/adr/README.md`

Every listed non-README blob is unchanged between Outcome 1 head `de027e33312be49e5b825c0abc7e864688ae2aaa` and candidate tip `d96b58ab55e932dda8b1cc007b7f88ad483f336e`. The later `docs/adr/README.md` additions are not Outcome 1 and must be separated.

### 3.3 Outcome 1 dependency and evidence boundary

- Exact base dependency: `8caab23bb4277121a77d80dc043b3c2c43b07ced`.
- Exact Outcome 1 head: `de027e33312be49e5b825c0abc7e864688ae2aaa`.
- Recorded hosted evidence: run `30218838605`, attempt 1, cited by accepted ADR 0065. It reports exact-16 acquisition, two fresh 4,353-entry builds, equality to committed manifest/ustar pins, cleanup, and final observation at `de027e33312be49e5b825c0abc7e864688ae2aaa`.
- Non-claims remain: no runtime assets, KVM/Kata lifecycle, network, SSH, workload, Phase B, production, or cloud authority.

## 4. Outcome 2 production code to move by extraction

### 4.1 Mixed source commit

`a7914db60cd5ed3a76c081299ab1b79c56455b21` is the only candidate commit containing reusable Outcome 2 production implementation. It is **not cherry-pickable**: one 4,691-addition commit mixes trusted closure code, runtime-archive discovery, a custom Phase B report/schema, native-preflight CI, and large test rewrites.

The extraction must retain source attribution to `a7914db...` but create new cohesive commits after the architecture gate.

### 4.2 Exact reusable production symbols

The main source is `deploy/aws-feasibility/remote/completion_kata_process.py` as added by `a7914db...`.

**Move into a dedicated trusted runtime-closure module, after redesign/review:**

- data models `HostElfObject`, `HostElfClosure`, and `_HostBound`;
- fixed-path/open/read policy in `_host_resolve` and `_host_read`;
- SONAME ambiguity handling in `_host_library`;
- exact close aggregation in `_close_host_bound`, `_close_descriptors`, and `_close_host_bounds`;
- transitive closure construction in `_host_closure`;
- generation-bound anonymous executable sealing in `_sealed_bound`;
- bounded descriptor readback in `_read_descriptor`; and
- actual executable-mapping authentication and map-drift check in `_mapped_closure`.

**Move as process-lifecycle design, not as an unchanged file:**

- `_set_parent_death_signal` and the corresponding `_child` handshake changes;
- `_wait_for_preinput_read`;
- `_archive_processes`, `_signal_archive_processes`, and `_cleanup_archive_child`;
- `ArchiveStreamIntent`, `ArchiveChildIdentity`, `ArchiveStreamOutcome`, and `_FixedArchiveStream`;
- `_recover_runtime_discovery_children` and `_runtime_discovery_process_residue`.

These are useful for the planned compression-executable and process-lifecycle jobs, but they are tied to runtime-discovery assets, global registries, and the old candidate runner. Rebuild them behind fixed trusted interfaces rather than copying the class wholesale.

**Use only as a design sketch:** `_RuntimeDiscoveryHost`. It currently validates the running candidate process (`os.getpid()`) instead of the plan's short-lived exact Python helper, uses mutable globals (`_DISCOVERY_FDS`, `_DISCOVERY_CHILDREN`), couples gzip/zstd execution to `completion_kata_runtime.FixedArchive`, and produces the old Phase B report domain.

### 4.3 Existing clean-head dependency to promote

`deploy/aws-feasibility/remote/completion_runtime_closure.py` already exists at the clean head and is not a candidate delta. Its strict `_elf` parser and ambiguity logic are the best portable foundation. Outcome 2 should extract/promote the private parser into an explicit reusable trusted parser API instead of having new code import `_elf` privately.

Required hardening before production reuse:

- separate host-object closure from the existing immutable-rootfs closure contract;
- authenticate fixed compile-time paths before any sandbox/capability drop;
- make the fresh exact-Python helper, not the long-lived runner, authoritative for mapped closure;
- bind the sealed gzip/zstd descriptors to the authenticated source generation;
- replace mutable global descriptor/process registries with one owned lifecycle object;
- define the new canonical closure-report schema before retaining the old report codec; and
- add portable hostile fixtures for missing/ambiguous libraries, drift, exhaustion, partial initialization, sealing failure, canonical output, and exact cleanup.

### 4.4 Reference-only candidate code

These `a7914db...` additions may inform design but should not move as code:

- `completion_kata_qualification.py`: strict scalar checking and canonical-report patterns are useful, but `RuntimeDiscoveryFacts`, its report shape, and schema loader describe runtime-archive discovery rather than Outcome 2's canonical closure report.
- `completion_kata_runtime.py`: the custom JSON-Schema interpreter and strict tar enumerator are Phase B runtime-archive machinery, not the Python/gzip/zstd host closure objective.
- `schemas/stage2-phase-b-qualification-v1.json`: wrong authority and report domain for Outcome 2.
- `scripts/run-stage2-phase-a-candidate.py` and `scripts/stage2-phase-a-budget.py`: one-shot candidate/evidence orchestration, not a trusted closure library.

## 5. Native-preflight research to discard

Discard from clean implementation history all native-preflight work beginning with ADR 0071 and every implementation/diagnostic after `a7914db...`. Do not port the giant embedded shell sandbox from `.github/workflows/ci.yml`.

The discarded research includes:

- iterative checkout fd handoff and post-sudo descriptor changes;
- CLOEXEC observer changes;
- direct libc bind and same-mount-namespace reopen attempts;
- root/checkout-owner/late-userns mapping attempts;
- descriptor-limit normalization;
- parent/child proc and final PID-namespace corrections;
- fixed diagnostic-label commits that only classify hosted-environment failures;
- the native fixture Gitleaks exception; and
- the coupled native matrices in the Kata-process and Phase A candidate tests.

Why it is discarded:

1. It tries to prove all native properties inside one increasingly complex sandbox, contrary to `OUTCOME-TWO-PLAN.md` Jobs A–E.
2. It performs host discovery after or inside capability removal, while the new trust boundary requires trusted preparation first.
3. It never reaches a clean successful native-preflight result at candidate tip; the final commits still classify namespace-transition failures.
4. Workflow implementation dominates the change and repeatedly adapts architecture to hosted-runner behavior without a prior capability report.
5. Its accepted ADR chain is research history, not a stable production API.

Useful observations may be restated as probe questions—sudo fd policy, `RLIMIT_NOFILE`, `close_range`, namespace mapping, proc ownership, `map_files`, mount behavior, and PID lifecycle—but no implementation commit should move. The new capability-report PR must be metadata-only and non-authoritative.

## 6. Exact candidate file disposition

### KEEP-O1

Use the 24-path Outcome 1 map in section 3.2. For `docs/adr/README.md`, keep only ADR 0057–0064 additions.

### SPLIT-O2 / source-reference

| Path | Disposition |
|---|---|
| `deploy/aws-feasibility/remote/completion_kata_process.py` | Extract only the symbols in section 4.2 into new trusted modules; do not move the file wholesale. |
| `deploy/aws-feasibility/remote/completion_kata_qualification.py` | Reference canonical/strict-validation patterns only; replace the old report domain. |
| `deploy/aws-feasibility/remote/completion_runtime_closure.py` | Already on clean head; promote/refactor its strict ELF parser under new tests. |

### DROP from clean PRs

- `.github/workflows/ci.yml` candidate delta
- `.github/workflows/stage2-phase-a-candidate.yml` candidate delta
- `.gitleaksignore`
- `deploy/aws-feasibility/remote/completion_kata_runtime.py` candidate delta
- `docs/adr/0065-authorize-local-phase-b-and-workload-qualification.md` through `docs/adr/0086-create-final-child-owned-pid-namespace.md`
- ADR 0065–0086 rows/history in `docs/adr/README.md`
- `schemas/stage2-phase-b-qualification-v1.json`
- `scripts/run-stage2-phase-a-candidate.py` candidate delta
- `scripts/stage2-phase-a-budget.py` candidate delta
- `scripts/validate-schemas.ts` Phase B registration delta
- `test/aws-stage2-completion-kata-process.py` candidate delta
- `test/aws-stage2-completion-kata-process.test.ts` candidate delta
- `test/aws-stage2-completion-kata-runtime.py` candidate delta
- `test/aws-stage2-completion-kata-runtime.test.ts` candidate delta
- `test/aws-stage2-completion-kata-s5.py` candidate delta
- `test/stage2-phase-a-candidate.py` candidate delta
- `test/stage2-phase-a-candidate.test.ts` candidate delta

The rootfs files/tests listed under KEEP-O1 must not be dropped merely because they coexist at candidate tip.

## 7. Clean PR boundaries and integration order

### PR 1 — Outcome 1 atomic rootfs

- **Base:** `8caab23bb4277121a77d80dc043b3c2c43b07ced`.
- **Head/tree:** exact first-parent Outcome 1 series through `de027e33312be49e5b825c0abc7e864688ae2aaa`.
- **Contents:** section 3.2 only.
- **Excludes:** ADR 0065+, general CI, Phase B schema/runner, Kata/runtime discovery, and native preflight.

This is the only PR that should preserve candidate commits directly.

### Outcome 2 clean base

After PR 1 is reviewed, create the Outcome 2 branch from its reviewed head and apply `908041cf6473c10667a030c11c6798cb2338c5d4` (the plan-only commit) onto it. Current clean head is exactly merge-base plus that plan, so this operation is conflict-independent of the Outcome 1 code.

### PR 2 — hosted-runner capability report

- New code only; no candidate commit cherry-pick.
- Metadata-only, no acquisition, no raw environment, no authority.
- Must land before the architecture ADR is finalized.

### Architecture gate

Combine all Wave 1 reports into one ADR that explicitly defines trusted/untrusted operations, report schema, cleanup obligations, native jobs, and supersession of the ADR 0065–0086 mechanisms. No production extraction before this gate.

### PR 3 — trusted runtime closure and portable tests

- Depend on the architecture ADR and reviewed Outcome 1 base.
- Promote the clean-head ELF parser.
- Reimplement/extract the trusted portions of `a7914db...` in dedicated modules with source attribution.
- Include portable hostile tests and the new canonical closure schema.
- Do not include workflow edits or native-preflight tests.

Although the plan lists portable tests with this PR, keep test fixtures/companions in separate commits so production and hostile coverage can be reviewed independently.

### PR 4 — native primitive qualification

- Depend on PR 2 facts and PR 3 contracts.
- Implement small independent Jobs A–E, not the discarded embedded native sandbox.
- Keep workflow orchestration thin; each job proves one primitive set.

### PR 5 — Outcome 2 integration/evidence

- Depend on PRs 3 and 4.
- Thin composition only: trusted closure, fixed descriptors/metadata, one gzip and one zstd workload, exact cleanup and deterministic report evidence.
- No parser branch testing or capability discovery here.

**Integration order:** PR 1 → plan on reviewed O1 head → PR 2 → architecture ADR → PR 3 → PR 4 → PR 5. PR 3 portable parser work may be prepared in parallel after the ADR, but PR 4 must not claim authority until PR 2 and PR 3 contracts are fixed.

## 8. Dependencies and uncertainty

### Dependencies

- Outcome 1 depends exactly on `8caab23...` and its fixed rootfs inputs/pins.
- Trusted closure depends on the clean-head strict ELF parser, fixed `/usr/bin/python3`, `/usr/bin/zstd`, `/usr/bin/gzip`, fixed library search policy, Linux fd/seal/proc primitives, and the new architecture/report contracts.
- Native work depends on actual capability-probe facts; do not infer them from failed workflow diagnostics.
- Integration depends on authoritative completion of all small native jobs and portable cleanup tests.

### Uncertainty / required revalidation

- This audit verified Git objects, history, path deltas, accepted decisions, and source structure; it did not independently download prior GitHub artifacts or replay the 1.55 GB hosted qualification.
- ADR 0065's recorded run is the Outcome 1 evidence source; its artifact availability and exact external metadata should be checked by the PR owner before merge.
- `a7914db...` production code has not been qualified under the new trusted-preparation architecture. It must receive new portable and hostile review.
- The existing ELF parser is strict but private and coupled to rootfs models; extraction may uncover unsupported host ELF variants.
- Hosted `/usr/bin/zstd`, procfs `map_files`, descriptor limits, and namespace behavior remain probe facts, not assumptions.
- Candidate tip has no successful final native-preflight evidence; no SHA after `a7914db...` should be cited as authority.
- The branch contains duplicate accepted-ADR commits from merged documentation ancestry. Selecting both versions would duplicate history/content; the exact KEEP-O1 first-parent list avoids that.

## 9. Audit checks performed

- Resolved clean head, candidate local/remote tip, merge base, and full graph.
- Enumerated all 119 candidate-only reachable commits and every changed path.
- Compared the exact Outcome 1 tree at `de027e333...` with candidate tip.
- Inspected accepted ADRs 0038–0086 relevant to issue #42 and Outcome 2.
- Inspected the strict ELF parser and the `a7914db...` trusted closure/process additions.
- `git diff --check 8caab23...d96b58ab`: pass.
- `git diff --check 8caab23...de027e333`: pass.
- No production file was modified and no qualification workflow was invoked.

## Appendix A — complete 119-commit disposition

`KEEP-O1` means preserve directly in PR 1. `SPLIT-O2` means source extraction only, never cherry-pick. `DROP` means omit from clean PR history while retaining it on the frozen research ref.

| Action | Commit | Subject |
|---|---|---|
| KEEP-O1 | `c25c851063ed654adf3bf1162004b8e8b513b7ef` | ADR 0057: atomic unnamed candidate-tar remediation (#226) |
| KEEP-O1 | `5522a53529d7a2a40a444f42c0f98fb472f68572` | Add atomic unnamed candidate tar transaction |
| KEEP-O1 | `f43b864306b02d3e87057440f4579dcd9cd08b6b` | ADR 0058: authorize atomic candidate test companions (#228) |
| KEEP-O1 | `8663d652fabc909e3f29f9bda898c54fedfd9fd3` | Reject regressive candidate parent transitions |
| KEEP-O1 | `bf598260752eecd0f9321d90dd33230fab60382c` | ADR 0059: authorize filesystem TypeScript companion (#229) |
| KEEP-O1 | `f40588eae988eb3236bdf654d8db32158621c96f` | Qualify atomic candidate tar lifecycle |
| KEEP-O1 | `b95fdb917e0dd580b8ef2cb0f2f30cec503435f3` | ADR 0060: raise hosted qualification driver cap (#231) |
| KEEP-O1 | `65ff8e4568eb882c28add0e9f174722e7698880a` | Complete hosted rootfs qualification protocol |
| KEEP-O1 | `6feccbe72589afdf3790dfc755a92bba9ccf071d` | Narrow filesystem companion source checks |
| KEEP-O1 | `e1da5af575ef3cfa4eaf9319b36144ff6ce7fd07` | ADR 0061: raise hosted failure-path cap (#232) |
| KEEP-O1 | `bc4d3673ef13538e5af987badcc027c572aa9e70` | Close hosted qualification failure paths |
| KEEP-O1 | `4fcfad33dcd2152e23ac00595faec7ddc0cd6356` | ADR 0062: signal-safe hosted driver cap (#233) |
| KEEP-O1 | `14fbda9f77506ba2140bd6b38913f96ae9535705` | Supervise hosted rootfs qualification out of process |
| KEEP-O1 | `35c4f922889e56c33def5e429604afd8ae4ad53b` | Accept ADR 0063 measured supervisor cap (#234) |
| KEEP-O1 | `79665f53f9c7ec1652d42d6c004159ad52b37b45` | Bind supervisor recovery and durable fault cuts |
| KEEP-O1 | `cb5b6e2f48af9d05769c75b1a1963506e220b906` | Accept ADR 0064 no-bytecode replacement run (#235) |
| KEEP-O1 | `de027e33312be49e5b825c0abc7e864688ae2aaa` | Prevent hosted fixed-source bytecode writes |
| DROP | `84b30d30b3307f1c5222dd9e50dfa755cdee673a` | Accept ADR 0065 local Stage 2 completion (#236) |
| DROP | `c04f4ce680d0f14efe9f89f19aad0e77d169c710` | Integrate ADR 0066 discovery lifecycle authority |
| DROP | `8c646c07dc1f5ded54f6f680b187a60939f71a65` | Add guarded Phase B discovery workflow |
| DROP | `fc4228bcc9afc20e42aae0b7b18a8910333c3c52` | Integrate ADR 0067 Phase B cap reallocation |
| DROP | `bfacac2f44b6560b2f7c648ef7ce5e9433bef25e` | Revert "Add guarded Phase B discovery workflow" |
| DROP | `9007608d3637f016a21974660104bf5a8c03ad77` | Integrate ADR 0068 split Phase B discovery |
| DROP | `6d01666e0a91d7299fc2ed2100faf829e5877bb2` | Integrate ADR 0069 runtime-discovery corrections |
| DROP | `18f26441b6115091233d0c4cd44ced8f058d014f` | Integrate ADR 0070 runtime-discovery boundaries |
| DROP | `7433f48017c4fab208938df04ec6507132422206` | ADR 0057: atomic unnamed candidate-tar remediation (#226) |
| DROP | `eb688eb285be42cba0e3aa0bb0fd91c13517ff52` | ADR 0058: authorize atomic candidate test companions (#228) |
| DROP | `7427cf3ea0d77633eed2db9776514555fbeeecac` | ADR 0059: authorize filesystem TypeScript companion (#229) |
| DROP | `5c623ea0bf212c09b46ad67dfbf405ca05f4d601` | ADR 0060: raise hosted qualification driver cap (#231) |
| DROP | `ec66bace1242831846ed3d84b3d7e07e2650947a` | ADR 0061: raise hosted failure-path cap (#232) |
| DROP | `e6243ef15e13d1a3f5d0d2428a69ba54618579dc` | ADR 0062: signal-safe hosted driver cap (#233) |
| DROP | `bccc545b9885144eca79160b4775c50456cdd54c` | Accept ADR 0063 measured supervisor cap (#234) |
| DROP | `28f5439e6f2680d95aaaca240024ac7201fc6261` | Accept ADR 0064 no-bytecode replacement run (#235) |
| DROP | `6e6524ddecc08a8cd43e18f7f1d11f312a53c64c` | Accept ADR 0065 local Stage 2 completion (#236) |
| DROP | `e21914a6b2b5fcfb7357a1c061d5ccbc4085d03a` | ADR 0066: authorize one authentic Phase B discovery lifecycle (#237) |
| DROP | `cf5975f1d9399fbde9cdd2475841bb731cd0a3ee` | ADR 0067: reallocate Phase B correction highs (#238) |
| DROP | `623a9184a543edf69d1961e1b5bad8e8c0ebe75f` | ADR 0068: split Phase B runtime and lifecycle discovery (#239) |
| DROP | `49802429c88d032c331373e46b1b8d1fa800b744` | ADR 0069: reallocate runtime-discovery correction highs (#240) |
| DROP | `40fbdc3c6b488469db9648bb21c4da3e80bf4490` | ADR 0070: correct runtime-discovery final boundaries (#241) |
| DROP | `287941771dc80a106f9b5e8ac51e9b4f027be0d7` | ADR 0071: authorize native runtime preflight (#242) |
| DROP | `e1b11022f31af342f47b5712d7c8acb75d5fc8bb` | Integrate accepted ADR 0071 native runtime preflight |
| DROP | `fd3ad161e5c90b91e485931858189315397eb356` | ADR 0072: correct native preflight boundaries (#243) |
| DROP | `a4a4c6f5a6be5c2eb0101a7c365e20cfe796607b` | Integrate accepted ADR 0072 native preflight corrections |
| DROP | `56744a26ca9f8e8eaa5bf568f131abe081c1519f` | ADR 0073: correct native final evidence findings (#244) |
| DROP | `96c244d2353903bfae0d7487916ed6987b8fa485` | Integrate accepted ADR 0073 native evidence corrections |
| DROP | `ddb93aaf53ca26fc1f37e09e805f49423a6618ae` | ADR 0074: narrow native preflight evidence (#245) |
| DROP | `779948d97c62a44ff9cdba357375a0b652febc00` | Integrate accepted ADR 0074 narrow native evidence |
| DROP | `db7f3059e692b7c45ca93655c2d256facb9d31fb` | ADR 0075: correct native sandbox UID mapping (#246) |
| DROP | `7d4fff2d9163d8792303547c0d6fb92befb4a283` | Integrate accepted ADR 0075 root namespace mapping |
| SPLIT-O2 | `a7914db60cd5ed3a76c081299ab1b79c56455b21` | Add guarded runtime discovery and native preflight |
| DROP | `51a9d85fb82174f3c6c80ee132fe01ba25095645` | Add bounded native preflight diagnostics |
| DROP | `eced071328f74b678b79e3ea87355ad9d05095ea` | Add fixed native failure classification |
| DROP | `ee619001422f37fc15cbf45d5c48c51b777b59e1` | Classify native bootstrap failures |
| DROP | `82be527310d72ca593dcb6483997da7edab9ba5e` | Classify trusted sandbox failures |
| DROP | `48414a2ebf48c38a1214f8e02438f7cd481f5c52` | Expand fixed sandbox failure classes |
| DROP | `66f89ab36d25b006a646a82bd924bddeabd4b747` | Ignore deterministic RFC key fixture fingerprint |
| DROP | `d87ff2e3c01ab79505491cb06bbf3cb4efb019e8` | Refine native permission failure classes |
| DROP | `e32ec35b3e92b01bcda391afa53f42bc3bbeaf56` | ADR 0076: authorize checkout descriptor handoff (#247) |
| DROP | `f422de12756bad20a34aee45a7f622a5b113ab40` | Integrate accepted ADR 0076 checkout descriptor |
| DROP | `f8373194f3aff5d9497ccb059e31f7898ad206c0` | ADR 0077: raise native workflow cap (#248) |
| DROP | `f7ab5691aac3c7cba028a38cdab0547e7d83c6ab` | Integrate accepted ADR 0077 native workflow cap |
| DROP | `dea5041191e36755b7a09ba897ebc4dca05489e5` | Bind native preflight checkout by descriptor |
| DROP | `0c74a0bf8c41e2e0f141dcaf1dbcd747254b3d35` | Classify descriptor sandbox failures |
| DROP | `e4650ab106fb3d69571ad9a4356c62b3aeb67100` | Keep native workflow within reviewed cap |
| DROP | `e787d66aa006705ca670da88a3b8236b8767d41b` | ADR 0078: create checkout descriptor after sudo (#249) |
| DROP | `35fc1fe8aaf343f049aa08b642468e667c01181e` | Integrate accepted ADR 0078 post-sudo checkout descriptor |
| DROP | `62b5de65f2a18044ec5c20b7380a59bbb335608e` | Create checkout descriptor after sudo |
| DROP | `a5ff639c606d79fcee2703505eeb419d4bd823d9` | Classify post-sudo launcher failures |
| DROP | `d53b1165f7a66170d3fcfd80d77e04e75f6f7359` | Observe trusted descriptor sets without heredoc fds |
| DROP | `2badf6a79dbb1ece909bf4a4709195e057dfc068` | ADR 0079: narrow trusted setup descriptor observation (#250) |
| DROP | `7dbf12f3a80ccb282d940fbc0cb7ebfeac75b657` | Integrate accepted ADR 0079 CLOEXEC observer |
| DROP | `509d49af8509ec93b98c4a3efb84defd6065c872` | Allow only CLOEXEC trusted setup descriptors |
| DROP | `e336ea0da37203c2f3787c6abb6023e6d44efc94` | Classify CLOEXEC observer failures |
| DROP | `2f9a3a87aa6e5ab8b5087c3fd078d5fe7eba08aa` | Bind fixed native failure classes |
| DROP | `2c4db02d31e35858e932c608a279972cc55b3e21` | Expand trusted native failure labels |
| DROP | `17839c0447507823d9ae62002a6b80d1b6544c75` | Classify namespace map mismatch |
| DROP | `192b723265af56626b90d845a89cc0df304eac77` | Resolve observer parent through mounted proc |
| DROP | `058e8736a5d1ebfa2a6598da784dffd4e9cda989` | Classify trusted mount failures |
| DROP | `3dd2b0ecb1d787b7d6e21b30fc0c4470de47ee99` | Refine trusted mount failure labels |
| DROP | `a8579c42c517e1c49eae11f78953ceeeba11fb64` | ADR 0080: use direct libc descriptor bind (#251) |
| DROP | `5f9efac38603a86a87cd32bc208c1552c465176d` | Integrate accepted ADR 0080 direct descriptor bind |
| DROP | `ea800becc6c3fdd95f09f1b0df584346130854de` | Bind checkout with direct mount syscall |
| DROP | `31448903693263267f2ece6e73b0b60407bd8eab` | Classify direct descriptor bind errors |
| DROP | `bed2d05b402e6aa7c5ebcd919b607c254fe5fdb7` | Refine descriptor bind errno labels |
| DROP | `8d708355a101f3e80af617e5d4a7bed8c2ae406e` | ADR 0081: open checkout in final mount namespace (#252) |
| DROP | `5f8415edac10fe7a7d78fbb00cf48b74282991fe` | Integrate accepted ADR 0081 same-namespace descriptor open |
| DROP | `249c66c65e45f55af1460aa45c65ad2e2325daa1` | Open checkout in final mount namespace |
| DROP | `9cb67fdad3dcd175f9931c42dcf4ff6b7704c758` | Refine two-stage launcher diagnostics |
| DROP | `dd5b9092a19abf1fe33991e23546f5e170b0cc67` | ADR 0082: map authenticated checkout owner (#253) |
| DROP | `ae6d30ceb2e948f55f286fccb749c0cbcbeb7b49` | Integrate accepted ADR 0082 exact checkout-owner map |
| DROP | `f010ac8f7ff0fc5647f6e9d83a1242a968325a62` | Map authenticated checkout owner exactly |
| DROP | `c59ce8662b45155cc8559a4528deaac17224fca2` | Refine exact map launcher diagnostics |
| DROP | `7d803ece4c0aa688a94500d04232ca164bc52cfb` | Keep exact map diagnostics policy-safe |
| DROP | `b8cd2cc29d76d9d89370961b44ca92de9aee1916` | Classify exact map text safely |
| DROP | `712857918e64663699bcf8d5d13fb4319a3a94d8` | Hash bounded native diagnostics |
| DROP | `85268e4b7f3ee8c71292974ad077589c5ae3031a` | ADR 0083: enter user namespace after trusted mount setup (#254) |
| DROP | `a1e0a3443aa3eacc11bbc84c7e104428f5b76e2a` | Integrate accepted ADR 0083 late user namespace |
| DROP | `d8d3a05f474df140e1651115948747b157daa5db` | Enter root-only user namespace after mount setup |
| DROP | `0968fa44577e06477a81ef7b0f0b00d1fffdb4c0` | Classify trusted tmpfs verifier failures |
| DROP | `69404a1a4310fa0ece86c1bfeb40994be96b836d` | Identify tmpfs verifier field mismatch |
| DROP | `f5da9ac6a1606e258ca1a5016c5a8a0610cf3000` | Match default tmpfs mode serialization |
| DROP | `a37ad4d82b07f87f65e217a19685d8b5e5d3d289` | Identify proc verifier field mismatch |
| DROP | `5607f71b9c004f55063f65e017bc4e8dfa32d597` | Classify proc superblock policy |
| DROP | `286b7824665b2e8ec79c1f3a9b5a07e3639fa566` | Require read-only proc superblock |
| DROP | `7021a55d7f0d2b305b8dc02e81fdfaceefdc2654` | Preserve already-cleared supplementary groups |
| DROP | `7282309a240b1a9314e0bcd57e2b8763415a492c` | Refine native descriptor setup phases |
| DROP | `b28ef9779a6f307ebaaf026d77256a0569980714` | ADR 0084: set native sandbox descriptor limit (#255) |
| DROP | `c990592a7e311f2500201f9db7b881c068e6ddd8` | Integrate accepted ADR 0084 descriptor limit |
| DROP | `4b508950ad3b0dca6c4073da9eac818e5410e213` | Normalize native descriptor soft limit |
| DROP | `0d5d9c49e7617ea426315e7084af524cd86c5b81` | Classify native host closure initialization |
| DROP | `35c139025ddeedca4ad16d72da2bd903f68f08f3` | Isolate native host binding stages |
| DROP | `86e6974d7ae2b39fb9ef40a06921db815ba9283f` | Isolate native mapped closure access |
| DROP | `cbbb4fb63403519ce3c37bc82211d5964d3e2e01` | Mount proc in final user namespace |
| DROP | `d9ef36e3c69564eb7017d70ad3eb6a3d173fefb9` | Bind final capability transition assertion |
| DROP | `152d866f5603e09b981e761438bd6febf3035a96` | ADR 0085: create child-owned proc superblock (#256) |
| DROP | `8431edd5272d8c61b07e0bbdddaa5e36a92b9844` | ADR 0086: create final child-owned PID namespace (#257) |
| DROP | `58d22d85f74a191f77988446eea1a64ebcd28476` | Integrate accepted ADR 0086 final PID namespace |
| DROP | `e1e007fb9385c8feac08440d1b68be88f7d33ab4` | Create final child-owned PID namespace |
| DROP | `d96b58ab55e932dda8b1cc007b7f88ad483f336e` | Classify final namespace transition failures |
