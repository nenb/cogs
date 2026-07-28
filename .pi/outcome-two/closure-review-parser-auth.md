# Outcome 2 Wave 2 hostile review — parser and trusted closure authentication

- Review ID: `O2-R-PARSER`
- Exact reviewed head: `64c055762e260b8fc2eed96741bdb30c89183f3c`
- Date: 2026-07-27
- Scope: accepted ADR 0087, `OUTCOME-TWO-PLAN.md`, Wave 1 closure/portable audits, and exact Outcome 2 parser, closure, launcher, schema, fixtures, and portable tests.
- Disposition: review only; no production or test changes.
- Verdict: **BLOCKED**. Two P0, two P1, and four P2 findings remain. No P3 finding was established. This is not hostile-review sign-off and grants no native, integration, AWS, provider, deployment, production, or issue-closure authority.

## Findings

### P0-1 — T1 executes the closure and parser before authenticating either implementation

`prepare_fixed_runtime_closure()` directly enters authority-bearing preparation through `_prepare(_Ops())` (`deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1212-1214`) after a bare `completion_elf` import (`:20`). There is no fixed `/usr/bin/python3 -I -B` bootstrap, empty fixed environment check, authenticated import root, or source-head/blob check before discovery, helper execution, mapping, and sealing. The only source authentication is later in the consumer (`completion_trusted_runtime_launcher.py:142-170`), and the consumer does not call it until a handoff already exists (`:523-539`). It authenticates only the closure file, not `completion_elf.py` or the already-running launcher.

This leaves the exact T1 trust admission unenforced: substituted parser/closure/launcher code can acquire host authority and manufacture a handoff before any check. Move authentication ahead of import/preparation and bind the complete transitive tracked implementation to the externally gated exact head.

### P0-2 — A caller can forge a type-correct handoff and execute descriptors unrelated to the report

`RuntimeClosureHandoff` has a public, token-free dataclass constructor (`completion_trusted_runtime_closure.py:79-83`). The launcher checks only regular-file shape, seals, CLOEXEC, and report read-only mode (`completion_trusted_runtime_launcher.py:175-196`). It validates report-internal digests (`:290-344`) but never hashes the gzip/zstd descriptors or compares their sizes/digests to the corresponding report executable objects before `_run_fixed_tool` (`:523-545`). The module/name check at `:145-149` is satisfied by directly constructing the exported tracked dataclass.

A caller can therefore provide sealed attacker-created gzip/zstd memfds plus an unrelated valid report; an executable that emits the fixed payload can produce a false qualification. Bind each executable descriptor byte-for-byte and by role/size to its report object before any exec, and make producer provenance enforceable rather than relying on forgeable Python type metadata.

### P1-1 — The later qualification execution is not bound to the authenticated loader/library generations

The closure authenticates and maps the original fixed tools (`completion_trusted_runtime_closure.py:740-797`), seals only gzip/zstd executable bytes (`:798-834`), then closes every authenticated source descriptor before readiness (`:1179-1181`). The handoff carries only those executable memfds and the report. On later `execveat`, the kernel/dynamic loader resolves the interpreter and `DT_NEEDED` providers again from the then-current host filesystem; the launcher neither retains/mounts the authenticated generations nor revalidates final mappings.

A loader/library replacement after T1 mapping and before launcher exec can make the qualified execution differ from the reported closure. The final launcher must execute in a namespace assembled from the authenticated generations or otherwise retain and bind exact loader/library authority through execution, then verify no closure expansion.

### P1-2 — Fresh helpers can inherit ambient caller descriptors

The helper child duplicates its gates and closes only `gate_read` and `devnull` conditionally before exec (`completion_trusted_runtime_closure.py:601-626`). It never closes/rejects arbitrary non-CLOEXEC descriptors present in the T1 baseline, and it does not reserve descriptors 0-2 before source acquisition. This violates the fixed minimal helper and “no caller descriptor may add authority” contracts; closed stdio can also let authenticated/source descriptors occupy 0-2 and be clobbered by `dup2`.

Reserve stdio before preparation and close all child descriptors except an exact allowlist using the required fixed descriptor primitive. Add hostile inherited-FD and every closed-stdio permutation tests.

### P2-1 — Cleanup-after fault coverage accepts the forbidden CLOSED-after-error transition

`PreparedRuntimeClosure.close()` sets `CLOSED` before its final checkpoint (`completion_trusted_runtime_closure.py:1069-1092`). The recovery suite injects `cleanup.after`, accepts the resulting exception, calls `close()` again, and requires success/CLOSED (`test/outcome-two-recovery-portable.py:168-178`; cut declared in `test/fixtures/outcome-two/recovery/cases.json:3`). That is the opposite of ADR 0087’s rule that an uncertain close repeats the same failure and never becomes success.

Although the system adapter’s checkpoint is currently a no-op, the hostile seam is asserting the wrong owner contract and can hide a future fallible post-close action. Publish CLOSED only after all fallible completion steps, or poison and repeat the same error; make the test require that behavior.

### P2-2 — The strict ELF parser models byte spans, not Linux page-granular PT_LOAD mappings

The parser permits `p_align` 0/1 and otherwise checks congruence only modulo `p_align`, then rejects overlaps and resolves virtual addresses using unrounded byte spans (`completion_elf.py:117-152`). Linux maps PT_LOAD extents at page granularity. Hostile page aliases or incongruent page offsets can make loader-visible bytes differ from the bytes selected by `mapped()`.

The later exact mapped-object equality is defense in depth, but ADR 0087 separately requires strict ELF64 correctness. Require the fixed x86-64 page congruence/profile and reject or correctly model page-rounded overlap, BSS, and remap order. Add p_align=1, page-alias, rounded-overlap, reversed-segment, and BSS hostile fixtures.

### P2-3 — Production does not perform the required tracked-schema plus independent semantic validation

Preparation calls the same `_validate_report_bytes` implementation twice (`completion_trusted_runtime_closure.py:1171-1174`). `_validate_report_bytes` is only the in-module codec/semantic validator (`:1006-1008`); production never validates against `schemas/trusted-runtime-closure-v1.json`, and the two calls are not independent implementations. The report test only inspects selected schema structure (`test/outcome-two-runtime-report-portable.py:100-112,115-137`).

Use the tracked schema validator and a separately implemented semantic codec, then independently re-encode/compare as ADR 0087 requires. Portable tests must prove divergence in either validator is terminal.

### P2-4 — Component/no-realpath and alias ambiguity coverage is not hostile enough

The closure’s descriptor-relative component walker and second-pass generation comparison are substantial improvements (`completion_trusted_runtime_closure.py:317-445`), and that module contains no `PATH` lookup or `realpath`. However, `FsOps` models only regular directories/files and never exercises symlink chains, `readlink`, `..`, absolute targets, component replacement, or rename races (`test/outcome-two-runtime-closure-portable.py:61-149`). The test also runs only `cases[:10]` (`:160-165`); its “same-inode-alias” fixture hardcodes inode 103 without binding it to the existing provider and is incorrectly expected to reject, so it proves neither allowed same-object aliases nor distinct-provider ambiguity.

The launcher separately authorizes its source root with `Path.resolve()` (`completion_trusted_runtime_launcher.py:45-46,149`) and opens only the final source component (`:225-238`). Its test hides this by scanning only the public-function suffix (`test/outcome-two-trusted-launcher-portable.py:137-139`). Add runtime sentinels that fail on `PATH`/`realpath`, exact component transcripts and symlink/rename generations, and correct same-identity/distinct-identity provider cases. Replace launcher source authorization with the same descriptor-relative authenticated component policy.

## Prior contract coverage

### Closed or materially improved from the Wave 1 closure audit

- Fresh fixed helpers replace the import-heavy long-lived Python process; exact resolved/mapped set equality and complete maps EOF/line/byte bounds are implemented (`completion_trusted_runtime_closure.py:587-797`).
- Fixed tool paths are compile-time literals; production parser/closure/tool execution performs no `PATH` lookup.
- Final executable/loader/library reads use held descriptors with root/mode/type/size and full generation checks, followed by a second logical-path component observation (`:317-445`).
- SONAME providers, missing/ambiguous candidates, ordered unique needed values, per-tool object/byte bounds, and aggregate byte bounds are present (`:453-552,1133-1137`).
- gzip/zstd sealing copies from held source descriptors, checks source generation before/after, verifies same-fd readback, and requires the exact executable seal mask (`:798-834`).
- Mapping digest, canonical metadata-only report, sealed report descriptor, one-shot settlement, and broad portable parser/mapping/sealing/lifecycle/report matrices now exist.

### Still open or regressed against accepted contracts

- Wave 1 P0 trusted-boundary enforcement remains open (P0-1).
- Exact handoff authority and final execution binding remain open (P0-2, P1-1).
- Fixed minimal helper descriptor authority remains open (P1-2).
- Poisoned/uncertain close semantics are contradicted by one recovery oracle (P2-1).
- Strict kernel-equivalent ELF correctness, tracked-schema independence, component hostile tests, and no-realpath launcher authorization remain incomplete (P2-2 through P2-4).
- No global cross-tool duplicate-role-identity hostile case was found; current aggregate deduplication at `completion_trusted_runtime_closure.py:1133-1137` is a byte count, not an explicit role-identity rejection.

## Measured line highs

Gross physical lines are measured from ADR 0087 predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa`; the schema-registration number is the Outcome 2 gross addition only. Fixture count is 241 physical lines across `test/fixtures/outcome-two/**` (binary fixture line delimiters included).

| Surface | Measured | High | State |
| --- | ---: | ---: | --- |
| `completion_elf.py` | 240 | 240 | **at high** |
| `completion_trusted_runtime_closure.py` | 1,220 | 1,220 | **at high** |
| `completion_trusted_runtime_launcher.py` | 599 | 600 | 1 remaining |
| trusted closure schema | 122 | 230 | 108 remaining |
| schema registration addition | 19 | 30 | 11 remaining |
| runtime-closure portable | 195 | 250 | 55 remaining |
| mapped-closure portable | 169 | 240 | 71 remaining |
| sealing portable | 156 | 210 | 54 remaining |
| lifecycle portable | 266 | 290 | 24 remaining |
| recovery portable | 249 | 290 | 41 remaining |
| report portable | 149 | 230 | 81 remaining |
| launcher portable | 149 | 280 | 131 remaining |
| TypeScript wrapper | 48 | 120 | 72 remaining |
| fixtures aggregate | 241 | 500 | 259 remaining |
| **Trusted/portable subtotal** | **3,822** | **4,730** | **908 remaining** |

No measured surface crosses its high, but both parser and closure are exactly at their non-transferable highs. ADR 0087 requires a new ADR before adding remediation lines to either; deletion does not create gross-addition credit.

## Checks

- `git rev-parse HEAD`: exact `64c055762e260b8fc2eed96741bdb30c89183f3c`.
- `git diff --check`: pass.
- Direct seven Python portable suites: pass.
- `npx tsx --test test/outcome-two-portable.test.ts`: pass (1/1 wrapper; all seven suites and optimized-mode rejection).
- `python3 -m py_compile` for parser/closure/launcher: pass.
- `npm run typecheck`: pass.
- `npm run lint`: pass.
- `npm run format:check`: pass.
- `npm run schemas`: pass (15 schemas and report semantics).
- `npm run lock:check`: pass.
- `npm run audit`: pass under the two recorded temporary dispositions through 2026-08-08.
- Full `npm test`: **not green** — 885 pass, 2 fail, 3 skip. The two failures are unrelated existing `dev-launcher-profiles.test.ts` fake-Docker log `ENOENT` cases (“insecure driver isolates docker tool state outside launcher controls” and “insecure driver preflights stale docker resources before creating launcher state”). Outcome 2 portable test 677 passed in that run.
- Native Jobs A-E and thin integration were not run and are not present as qualifying exact-head evidence in this review.

## Required disposition

Do not sign off or advance to native qualification/integration. Resolve P0-1 and P0-2 before treating any handoff as trusted; bind final loader/library generations and exact helper descriptors; correct the cleanup oracle; close parser/schema/component hostile gaps; adopt a new ADR for the parser/closure line-high changes; then obtain a fresh exact-head hostile review.

O2-R-PARSER COMPLETE
