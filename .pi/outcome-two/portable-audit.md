# Outcome 2 portable-test audit

**Audit target:** `feat/issue42-candidate-tar-remediation` at `d96b58ab55e932dda8b1cc007b7f88ad483f336e`  
**Audit branch:** `research/outcome2-portable`  
**Outcome 2 contract:** `OUTCOME-TWO-PLAN.md` at the clean Outcome 2 head, plus root `DESIGN.md` and `SECURITY.md`; target-branch ADRs 0071–0074 were used to classify portable and native claims.

## Conclusion

The target has a strong synthetic ELF parser suite and a strong Phase B candidate-report schema/codec suite, but it does **not** have the complete portable hostile suite required by Outcome 2.

The largest gaps are on the production host-side paths in `deploy/aws-feasibility/remote/completion_kata_process.py` and `scripts/run-stage2-phase-a-candidate.py`:

- no portable valid or hostile test drives `_host_read`, `_host_library`, and `_host_closure` as a unit;
- no portable maps fixture drives a successful `_mapped_closure`, changed maps, unknown mappings, cardinality, dependency, or mapping-bound failures;
- no portable sealing fault matrix drives `_read_exact_source`, `_sealed_memfd`, or `_sealed_bound`;
- no portable descriptor-exhaustion or production archive-child failure matrix exists;
- no portable test drives `_runtime_initialize`, `_runtime_load`, `_runtime_recover`, `_runtime_observe`, `_runtime_cleanup`, export cleanup, or final residue;
- no test proves byte-identical Outcome 2 report bytes from two independent executions, and the candidate schema has no mapping digest.

Accordingly, the existing native preflight supplies useful **native primitive evidence**, but it cannot substitute for the missing portable parser/fault/recovery branches.

## Evidence classification

| Classification | Meaning in this audit |
|---|---|
| **Portable behavioral evidence** | Runs in the ordinary test route with no native selector, fixed host runtime, namespace root, or real `/proc/<pid>/map_files` requirement. Mocks and synthetic bytes are acceptable when they drive production behavior. |
| **Static evidence** | Source/regex assertion only. It proves text is present, not that a branch works or cleans up. |
| **Native evidence** | Requires `COGS_REQUIRE_NATIVE_RUNTIME_PREFLIGHT_V1=1`, Linux amd64, the hardened CI namespace/chroot, real host tools/procfs/memfd/`close_range`, or real `O_TMPFILE`. It is not portable evidence. |
| **Adjacent evidence** | Tests rootfs/tar/mount/asset behavior that is useful prior art but does not exercise the Outcome 2 host runtime closure. |

ADR 0074 explicitly requires portable ownership, journal, report, export, crash, recovery, parser, schema, and budget behavior separately from the narrow native primitive set. This audit applies that split.

## Existing Outcome 2 test inventory

| Exact test/file | Ordinary behavior actually exercised | Classification |
|---|---|---|
| `test/aws-stage2-completion-runtime-closure.test.ts` — `F2 portable ELF parser and resolver reject hostile synthetic inputs` | Runs `test/aws-stage2-completion-runtime-closure.py` without `--real`; statically checks the pure closure module. | Portable behavioral + static. |
| `test/aws-stage2-completion-runtime-closure.py` — `elf()`, parser hostile matrix, `_regular`/`_library` cases | Synthetic ELF64 parsing, fixed interpreter policy, dynamic-tag rejection, malformed names, duplicate `DT_NEEDED`, graph links, candidate ambiguity, SONAME mismatch, duplicate closure SONAME. Its parser is relevant because `_host_read` calls `completion_runtime_closure._elf`. | Portable behavioral, but only the pure parser/archive-graph layer. |
| `test/aws-stage2-completion-runtime-closure.py --real` — `real_exact_cache_test()` | Fixed 35-object rootfs archive closure and deterministic manifest over the locally acquired 16-artifact cache. The ordinary TypeScript test does not invoke it. | Non-ordinary exact-cache/integration evidence; not a portable gate. |
| `test/aws-stage2-completion-kata-process.test.ts` — `S1 portable process suite and narrow native boundary remain exact` | Runs the default Python route, rejects `-O`, then checks production/native workflow source by regex. | Small portable behavioral matrix + substantial static evidence. |
| `test/aws-stage2-completion-kata-process.py` default route | Contract canonicality/digest/type rejection; recovery classification; mapped/host/runtime close-error aggregation; second `RuntimeDiscoveryHost.close()` rejection. It does not start the production archive child. | Portable behavioral, incomplete. |
| `test/aws-stage2-completion-kata-process.py` selected route — `_native_runtime_preflight()` | Real fixed Python/gzip/zstd closure, real Python mappings, real sealed gzip/zstd descriptors, genuine decompression children, inherited fd 198/4096 closure, PDEATHSIG before/after release, reap/residue, final fd baseline. | Native evidence only. |
| `.github/workflows/ci.yml` — `native-runtime-preflight` | Hardened Linux-amd64 namespace/chroot/proc/descriptor execution envelope for the selected process and publication companions. | Native execution-envelope evidence. |
| `test/aws-stage2-completion-kata-s5.test.ts` / `test/aws-stage2-completion-kata-s5.py` | Constructs typed `HostElfClosure`/archive/process facts, calls `canonical_runtime_discovery_report`, loads it through schema and strict codec, and rejects structural/semantic mutations. | Portable report/codec evidence; facts are synthetic, not closure acquisition. |
| `test/stage2-phase-a-candidate.test.ts` — `runtime-discovery schema is structurally exact and codec separately enforces semantics` | AJV schema checks plus production `load_runtime_discovery_report`; missing loader, unresolved dependency, wrong digest/total/order/aggregate, malformed structure, authority, claims, blockers, and duration cases. | Portable schema/codec evidence. |
| `test/stage2-phase-a-candidate.test.ts` — `Phase A pure downloader, KVM ioctl, and non-authority policies` / default `test/stage2-phase-a-candidate.py` | Broad candidate-runner generated and fault tests. Outcome 2-relevant portions cover journal parsing, generation drift, strict canonical reports, filesystem descriptor closure, rootfs recovery accounting, `_RuntimeJournalOwner` callback sequencing, and foreign runtime-owner rejection. | Portable, but mostly adjacent Phase A/rootfs behavior. It does not exercise the production Phase B runtime lifecycle. |
| `test/aws-stage2-completion-rootfs-candidate.test.ts` / default `test/aws-stage2-completion-rootfs-candidate.py` — `portable_supervisor_tests()` | Generated artifact-cache child cuts and fd cleanup. | Adjacent rootfs/candidate evidence, not host closure recovery. |
| `test/aws-stage2-completion-rootfs-candidate.py --linux-synthetic` — `linux_synthetic_faults()` | F1–F6 atomic candidate-tar recovery on a Docker-specific root tmpfs. The ordinary TypeScript test only asserts this mode exists; it does not run it. | Non-ordinary adjacent functional evidence. |
| `test/aws-stage2-completion-kata-runtime.test.ts` / `.py` | Mount/spec/process/share contracts and tar enumeration. | Adjacent; no host ELF or mapped closure evidence. |

A notable false-positive risk is the workflow variable `COGS_REQUIRE_ROOT_RUNTIME_CRASH_MATRIX_V1=1`: it is set in `.github/workflows/stage2-phase-a-candidate.yml`, but `test/stage2-phase-a-candidate.py` never reads it. Its presence therefore selects no crash matrix.

## Coverage matrix

Status: **Covered**, **Partial**, **Native-only**, or **Missing** refers to portable Outcome 2 evidence at the audited target.

| Area | Portable status | Exact existing portable evidence | Native/adjacent evidence that must not be counted as portable closure evidence | Exact missing tests and fixtures |
|---|---|---|---|---|
| **ELF parsing** | **Partial** | `test/aws-stage2-completion-runtime-closure.py`: `elf()` and the header/program-header/dynamic/string/name hostile matrices; `_require_root_interpreter`; truncation, overflow, overlap, alignment, duplicate tags/needed, unknown interpreter, and forbidden dynamic metadata. | Selected `_native_runtime_preflight()` parses real host ELF. `--real` checks the immutable rootfs archive closure, not synthetic host descriptor behavior. | Missing `test/outcome-two-runtime-closure-portable.py` scenarios `elf_valid_host_closure`, `elf_missing_loader`, `elf_missing_library`, `elf_oversized_host_object`, and `elf_object_count_129`. Missing fixtures `test/fixtures/outcome-two/elf/valid-executable.elf`, `valid-loader.elf`, `valid-libalpha.elf`, `missing-pt-interp.elf`, `unknown-interpreter.elf`, and `oversized-object.json`. These must drive `_host_read`/`_host_closure`, not only `_elf` helpers. |
| **Ambiguity** | **Partial** | `test/aws-stage2-completion-runtime-closure.py`: two-directory `libdup.so` ambiguity, SONAME missing/mismatch, `_claim_soname` duplicate identity, malformed candidate not ignored. Process contract rejects duplicate JSON keys and noncanonical library lists. | A successful real host resolution does not prove rejection of a second candidate. | Missing scenarios `host_duplicate_library_candidate`, `host_duplicate_role_fingerprint`, `host_same_inode_alias_is_not_ambiguous`, `host_two_distinct_candidates_are_ambiguous`, and `host_unresolved_dependency`. Missing fixtures `test/fixtures/outcome-two/closure/duplicate-library-candidates.json`, `same-inode-aliases.json`, `duplicate-role.json`, and `unresolved-needed.json`, injected into production `_host_library`/`_host_closure`. |
| **Drift / generation binding** | **Partial** | Pure graph `_regular` rejects a content SHA mismatch. Default `stage2-phase-a-candidate.py` has extensive rootfs/journal generation drift cases, but those are not host ELF reads. | Native host/mapped reads observe stable real objects once; they do not force drift. | Missing scenarios `host_mode_owner_policy_rejected`, `host_generation_changes_during_read`, `host_short_read`, `host_source_replaced_after_authentication`, `mapped_generation_changes_during_read`, and `closure_revalidation_after_resolution`. Missing scripted fixtures `test/fixtures/outcome-two/io/host-read-generation-change.json`, `host-short-read.json`, `host-mutable-policy.json`, and `mapped-read-generation-change.json`. The checks must cover dev/inode/size/mtime/ctime and root owner/non-writable policy through production calls. |
| **Mapped closure** | **Missing** (success and hostile branches); cleanup-error path only | Default process test forces `_mapped_closure(123, None)` to fail while reading maps and verifies both opened fds are attempted on close. No portable successful mapping capture exists. | Selected `_native_runtime_preflight()` uses real self maps and archive-child maps, checks pre-input ordering, real map descriptors, stable fd baseline, and expected closure matching. This is the strongest native-only area. | Missing `test/outcome-two-mapped-closure-portable.py` scenarios `mapped_stable_exact_closure`, `mapped_maps_changed_during_capture`, `mapped_unknown_executable_mapping`, `mapped_unopenable_executable_mapping`, `mapped_duplicate_fingerprint_ambiguity`, `mapped_missing_loader_role`, `mapped_missing_dependency`, `mapped_object_count_129`, `mapped_byte_bound`, and `mapped_executable_cardinality`. Missing fixtures `test/fixtures/outcome-two/maps/stable/maps-before.txt`, `stable/maps-after.txt`, `changed/maps-after.txt`, `unknown-executable.json`, `duplicate-fingerprint.json`, `missing-loader.json`, and `missing-needed.json`, plus referenced synthetic ELF blobs. They must call `_mapped_closure`, not a reimplemented validator. |
| **Sealing** | **Missing** failure matrix; success is native-only | Default TypeScript test only regex-checks the seal mask. Default Python does not call `_sealed_memfd` or `_sealed_bound`. | Selected `_native_runtime_preflight()` calls `_sealed_bound` for gzip/zstd and genuine archive execution indirectly seals both executables. | Missing `test/outcome-two-sealing-portable.py` scenarios `seal_success_exact_bytes_and_mode`, `seal_source_drift_before_copy`, `seal_partial_write`, `seal_fsync_failure`, `seal_rebound_digest_mismatch`, `seal_add_seals_failure`, `seal_get_seals_missing_bit`, `seal_close_failure`, and `seal_source_fd_closed_after_settlement`. Missing fixture `test/fixtures/outcome-two/sealing/fault-script.json` enumerating each before-/after-effect cut and required fd dispositions. Tests must drive `_read_exact_source`, `_sealed_memfd`, and `_sealed_bound`. |
| **Descriptor and process cleanup** | **Partial** | Default process test verifies non-short-circuit close aggregation in `_mapped_closure`, `_host_closure`, and `RuntimeDiscoveryHost.close`; it rejects a second host close. Candidate/rootfs tests provide generic fd/child cleanup prior art. | Native preflight proves low/high inherited fd closure, real child reap, PDEATHSIG, no mapped fd leak, no descendant, and final fd baseline. | Missing `test/outcome-two-lifecycle-portable.py` scenarios `descriptor_exhaustion_each_open_site`, `partial_host_initialization_cleanup`, `partial_runtime_host_initialization_cleanup`, `archive_setup_failure_cleanup`, `archive_exec_failure_cleanup`, `archive_status_pipe_failure_cleanup`, `archive_read_failure_cleanup`, `archive_wait_failure_cleanup`, `archive_pidfd_failure_cleanup`, `archive_selector_failure_cleanup`, `cleanup_primary_plus_all_close_errors`, `double_close_detected_without_reuse`, and `no_residual_tracked_fds_or_children`. Missing fixtures `test/fixtures/outcome-two/lifecycle/emfile-open-sites.json`, `archive-fault-sites.json`, and `partial-initialization.json`. Existing test-only `_make_test_issuer`/`open_fixed_process_owner` seams are not invoked anywhere on the target. |
| **Crash recovery** | **Missing** for runtime closure; adjacent rootfs recovery is broad | `_recovery_class` has exact/absent/unknown/mismatch unit cases. Default `stage2-phase-a-candidate.py` tests rootfs recovery retries and `_RuntimeJournalOwner` callback ordering, but does not invoke runtime recovery. | Native parent-death tests prove kernel/process primitives, not durable production recovery. Rootfs candidate F1–F6 and portable artifact supervisor cuts concern different transactions. | Missing `test/outcome-two-recovery-portable.py` scenarios `recover_intent_only`, `recover_started_exact_live`, `recover_started_absent`, `recover_started_identity_mismatch_preserves`, `recover_settled`, `recover_nonterminal`, `recover_corrupt_journal`, `recover_duplicate_callback`, `recover_owner_partial_initialization`, `recover_report_publication_each_cut`, `recover_export_each_cut`, `recover_cleanup_failure_preserves_uncertainty`, and `recovery_fresh_process_no_inherited_state`. Missing fixtures `test/fixtures/outcome-two/recovery/intent-only.jsonl`, `started-live.jsonl`, `started-absent.jsonl`, `started-mismatch.jsonl`, `settled.jsonl`, `nonterminal.jsonl`, `corrupt.jsonl`, and `partial-owner.jsonl`. Tests must drive `_runtime_initialize`, `_runtime_load`, `_runtime_recover`, `_recover_runtime_discovery_children`, `_runtime_cleanup`, `_runtime_cleanup_export`, and `_runtime_final_residue`. |
| **Schema / codec determinism** | **Partial (strong rejection, missing repeatability/mapping contract)** | `test/stage2-phase-a-candidate.test.ts` compiles `schemas/stage2-phase-b-qualification-v1.json`, independently canonicalizes, and checks production decode. It covers structural and semantic rejection including missing loader, unresolved needed, closure digest/total/order/aggregate, claims and authority. `test/aws-stage2-completion-kata-s5.py` round-trips a generated synthetic report and rejects malformed/noncanonical bytes. | A Phase B candidate report is explicitly non-authoritative. It is not the final Outcome 2 schema promised by the plan. | Missing `schemas/outcome-two-runtime-closure-v1.json`; missing fields/tests for `mapping_sha256` (or an equally explicit mapping digest), fixed schema version, and approved-path redaction. Missing `test/outcome-two-runtime-report-portable.py` scenarios `report_two_independent_runs_byte_identical`, `report_input_enumeration_order_irrelevant`, `report_mapping_digest_change_detected`, `report_duplicate_key_rejected`, `report_noncanonical_bytes_rejected`, `report_schema_every_required_field`, `report_no_environment_addresses_output_or_identifiers`, and `report_only_approved_fixed_paths`. Missing golden fixture `test/fixtures/outcome-two/reports/runtime-closure-v1.canonical.json` and hostile fixture set `test/fixtures/outcome-two/reports/hostile/`. |

## Outcome 2 plan checklist against the target

| Required portable case from `OUTCOME-TWO-PLAN.md` | Result |
|---|---|
| Valid ELF closure | **Partial:** parser and optional exact rootfs cache; no synthetic production host closure. |
| Missing loader | **Partial:** schema mutation/direct helper, not host resolver. |
| Missing library | **Partial:** resolver mismatch behavior, no top-level host closure fixture. |
| Duplicate library candidate | **Partial:** pure archive resolver only. |
| SONAME mismatch | **Partial:** pure resolver and contract only. |
| Unknown interpreter | **Covered at `_elf` parser level**; no `_host_closure` case. |
| Oversized object | **Missing at host read**; only report/contract aggregate arithmetic. |
| Mutable object | **Missing at host read.** |
| Generation change during read | **Missing for host and mapped ELF.** |
| Mapping changed during capture | **Missing portable; native success only.** |
| Unknown executable mapping | **Missing portable.** |
| Closure byte bound | **Partial:** contract/report arithmetic; no production host resolver fault fixture. |
| Object-count bound | **Missing explicit 129-object production test.** |
| Descriptor exhaustion | **Missing.** |
| Partial initialization | **Partial narrow host-cache close case; no constructor/open-site matrix.** |
| Failure while sealing | **Missing.** |
| Failure during cleanup | **Covered narrowly for close aggregation; missing process/runtime transaction matrix.** |
| Double close | **Partial:** second `RuntimeDiscoveryHost.close()` rejection; no fd-reuse hostile case. |
| Canonical encoding stability | **Partial:** canonical round trip; no two-execution byte equality. |
| Schema rejection | **Covered for the Phase B candidate schema, not a final Outcome 2 schema.** |
| No residual tracked descriptors or children | **Native-only for real closure children; portable adjacent checks do not run the archive child.** |

## Exact portable work package implied by the gaps

The following names are recommendations for the missing Wave 2 test ownership; they do not exist at the audited target:

1. `test/outcome-two-runtime-closure-portable.py` with one production-call scenario for every ELF, ambiguity, drift, byte, and object-count row above.
2. `test/outcome-two-mapped-closure-portable.py` backed by `test/fixtures/outcome-two/maps/` and the same synthetic ELF blobs.
3. `test/outcome-two-sealing-portable.py` with a scripted fd/memfd/fcntl fault adapter.
4. `test/outcome-two-lifecycle-portable.py` invoking the production archive supervisor and all existing test-only process seams.
5. `test/outcome-two-recovery-portable.py` driving production runtime owner/journal/report/export recovery in fresh subprocesses.
6. `test/outcome-two-runtime-report-portable.py` plus `schemas/outcome-two-runtime-closure-v1.json` and a canonical golden report.
7. One ordinary TypeScript wrapper, `test/outcome-two-portable.test.ts`, that runs all six Python files with no native selector, bounded timeouts, `PYTHONDONTWRITEBYTECODE=1`, and explicit optimized-mode rejection.

Synthetic fixtures should remain data-only and bounded. Native jobs should continue to prove real procfs, `map_files`, `memfd`, `close_range`, PDEATHSIG, gzip/zstd execution, and kernel cleanup, but should not absorb these parser/fault/recovery matrices.

## Audit execution

The following targeted ordinary tests passed against exact target worktree `d96b58a`:

```text
python3 test/aws-stage2-completion-runtime-closure.py
python3 test/aws-stage2-completion-kata-process.py
python3 -I test/aws-stage2-completion-rootfs-candidate.py
tsx --test \
  test/aws-stage2-completion-runtime-closure.test.ts \
  test/aws-stage2-completion-kata-process.test.ts \
  test/aws-stage2-completion-rootfs-candidate.test.ts \
  test/stage2-phase-a-candidate.test.ts

tsx --test \
  test/aws-stage2-completion-kata-runtime.test.ts \
  test/aws-stage2-completion-kata-s5.test.ts
```

Results: the three direct Python routes passed; all ten selected TypeScript subtests passed. No native selector, Docker synthetic mode, exact-cache acquisition, workflow, network, KVM, cloud, or deployment action was run. Passing these tests confirms the inventory above; it does not close the identified gaps.
