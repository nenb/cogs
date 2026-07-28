# Outcome Two native final E/integration signoff review

- **Implementation head reviewed:** `ea6e74fe709e02061e13be78922da13a8cf6f748`
- **Review scope:** Job E, thin integration, their tests, admitted launcher/closure interaction, native common report transaction/schema/workflow, and controlling ADRs 0087–0090.
- **Method:** fresh hostile exact-head static and portable review only. No `--workflow-bound` selector, sudo, namespace, mount, seccomp, `map_files`, compression qualification, native workflow, provider, AWS, or cloud operation was invoked.
- **Disposition:** **BLOCKED** — no P0 or P3; four P1 findings and one P2 finding remain.

## Findings

### P1-1 — E and integration still execute mutable checkout pathnames before fixed source admission; E's root route also rejects the intended runner-owned checkout

Job E reads a held source set, but its sole sudo command first asks root Python to execute the checked-out `job-e-sandbox.py` pathname. Root mode then opens the checkout and executes the checked-out launcher pathname (`scripts/native-qualification/job-e-sandbox.py:207-220,323-345`). Thin integration likewise executes the launcher by relative checkout pathname after an outer held-byte read (`scripts/native-qualification/thin-integration.py:135-151`). The held launcher bytes are used for an asserted digest and for an unprivileged result decoder; neither subprocess is created by compiling/executing that held admitted generation.

The launcher authenticates its source tree only after Python has already loaded and started executing that pathname (`deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1836-1871`). A replacement between the outer read and exec therefore runs before the claimed descriptor/source admission, with host root authority in E. The clean-worktree shell check does not close that TOCTOU boundary.

The E route is also incompatible with the launcher's own authority check. E passes fd 4 for the ordinary actions/checkout tree while running as host root (`job-e-sandbox.py:341-345`), but the launcher requires `root.st_uid == os.geteuid()` (`completion_trusted_runtime_launcher.py:1863-1867`). The workflow never transfers checkout ownership to root. On the intended GitHub runner, the runner-owned checkout cannot satisfy this root-owned check, so E fails before production T2 rather than qualifying it.

### P1-2 — Job E selects the full integration coordinator, not a fixed production sandbox-probe entry; thin integration still owns a parallel bootstrap implementation

Both E and integration emit `cogs.runtime-source-admission/v1` (`job-e-sandbox.py:176-183`; `thin-integration.py:125-128`). The launcher maps that version to `runtime`; there is no sandbox-probe admission mode or fixed sandbox-probe production entry (`completion_trusted_runtime_launcher.py:10-11,1856-1879`). Runtime mode invokes `_coordinate_with_ops`, which prepares the closure and runs both real gzip and zstd workloads (`completion_trusted_runtime_launcher.py:1669-1739`). Thus E repeats closure/compression/integration behavior instead of the accepted minimal Job E probe and cannot independently qualify only the sandbox boundary.

Thin integration does not merely call a fixed admitted production invoker. It implements its own admission codec, user-namespace setup, identity-map writes, fd layout, four-pipe transport, fork/pidfd supervisor, and exec wrapper (`thin-integration.py:125-260`). This contradicts ADR 0090's requirement that integration own no parallel admission, unshare, pipe, process, root, mount, or cleanup implementation. Workflow-level independence is present (fresh job, no A–E artifact download), but implementation independence/thinness is not.

### P1-3 — The E/integration outer owners are not all-path preregistered and do not independently prove the actual production residue domain

In both `_sudo_launch` and `_launch`, four `pipe2` calls occur before the ownership set and protecting `try` block (`job-e-sandbox.py:226-233`; `thin-integration.py:171-178`). Failure on pipe 2–4 leaks every earlier pair into report construction. Several close paths remove an fd from `owned` before the fallible close, and cleanup after an expired shared deadline can send KILL without retaining time to observe reap. The pidfd-unavailable fallback uses raw PID signaling and can also exhaust the same deadline without reap. The focused tests only regex-match gates/pidfds/deadlines; they inject no open/pipe/fork/pidfd/write/read/close/TERM/KILL/reap cuts.

The independent outer `paths` baseline is for `/run/cogs-o2-runtime-v1` in both drivers (`job-e-sandbox.py:366-375`; `thin-integration.py:280-289`), while the production launcher creates `/tmp/cogs-o2-runtime-v1` (`completion_trusted_runtime_launcher.py:30,1669-1676`). A production cleanup defect in the actual private root is therefore not detected by the required outer before/after path observation. Production result booleans cannot substitute for that independent baseline. These gaps prevent bounded preregistered cleanup and zero-residue signoff.

### P1-4 — Common post-upload cleanup is pathname-based, not identity-bound

`cleanup_report()` validates an opened report generation and compares one pathname stat, but then closes the descriptor and calls `_remove_owned()` (`scripts/native-qualification/common.py:368-389`). `_remove_owned()` blindly unlinks `.report.tmp` and `report.json` by name (`common.py:252-277`). A replacement after the last stat and before unlink is deleted as though it were the validated publication; failure cleanup can likewise delete an unregistered colliding name. The function can then fsync/rmdir and report successful baseline restoration despite having lost exact object authority and removed a foreign generation.

This violates ADR 0090's identity-bound unlink/publication lease and blocks the atomic report lifecycle even though report bytes are canonical, schema/semantic validation is applied, and upload cleanup is wired under `always()`.

### P2-1 — Portable acceptance does not exercise the required hostile report and launcher-wrapper cuts

The only common publication test is a Linux-only happy path and is skipped on this portable review host (`test/native-qualification-common.test.ts:154-170`). It checks source tokens rather than injecting the required short/interrupted I/O, before/after fsync/fstat/close, fd reuse, reopen/read, canonical/schema/semantic divergence, collision, replacement, directory-fsync, staged unlink, post-upload unlink, and upload-failure cuts.

The E/integration fixtures construct every production boolean as prefilled `true` (`test/native-qualification-e.test.ts:25`; `test/native-qualification-integration.test.ts:25`) and test result-shape rejection, but do not drive the actual workflow bootstrap route or distinguish sandbox-probe mode from full runtime mode. Static regex assertions therefore pass while P1-1 through P1-3 remain live. ADR 0090's portable completion gate is not met.

## Confirmed properties

- Static search found sudo only in Job E among A–E/integration, with fixed `sudo -n --close-from=3`, `env -i`, and no preserved descriptors above 2.
- The loaded `RuntimeQualificationResult` field order is compared exactly against the closed string/boolean inventory. E and integration reject missing, extra, renamed, false, wrongly typed, malformed, and substitute result values. No unknown-field/substitution finding remains in that decoder.
- The production launcher contains a real namespace/root/capability/NNP/seccomp/exec/map/readback T2 coordinator; the blocker is E's admission and selection of it, not absence of all production T2 machinery.
- Workflow jobs are fresh-runner siblings after Quality; integration needs A–E and downloads none of their artifacts. The final `always()` result requires all eight dependency results to be `success`.
- Native reports are canonical metadata/digest-only values with closed job/check/result/cleanup schema branches. No raw diagnostic, PID, fd, map row, mount ID, generated payload, credential, or A–E artifact is included.
- ADR 0090 file/native-subtotal highs and exact correction-range `diff --check` pass.

## Portable/static commands

After dependency provisioning with `npm ci --ignore-scripts --no-audit --no-fund`:

- `npx tsx --test test/native-qualification-{common,a,b,c,d,e,integration}.test.ts` — **27 pass, 1 skipped** (Linux-only common publication test).
- `npx tsx --test test/outcome-two-portable.test.ts` — **4 pass**.
- `npx tsc --noEmit` — **pass**.
- `npm run schemas` — **pass** (16 schemas plus examples, negatives, and semantics).
- scoped `biome check`, Python `py_compile`, ADR-range `git diff --check`, and native high accounting — **pass**.

Passing suites do not override the source/ownership defects above.

# BLOCKED

Do not authorize a native selector, Job E/integration run, artifact reliance, or Outcome Two signoff at `ea6e74fe709e02061e13be78922da13a8cf6f748`. Resolve every P1/P2 finding and obtain another exact-head hostile review.
