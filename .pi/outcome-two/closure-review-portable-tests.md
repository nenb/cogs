# Outcome 2 Wave 2 hostile review — portable tests

**Disposition:** **BLOCKED — unresolved P1/P2 findings**  
**Exact reviewed head:** `64c055762e260b8fc2eed96741bdb30c89183f3c` (`64c0557`)  
**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`  
**Review scope:** accepted `docs/adr/0087-prepare-runtime-closure-before-capability-drop.md`, `OUTCOME-TWO-PLAN.md`, `.pi/outcome-two/{closure-audit,portable-audit}.md`, exact trusted-closure/parser/launcher/schema production, all seven Outcome 2 portable Python suites, their TypeScript wrapper, fixtures, prior parser tests, and schema registration.  
**Change policy:** review only. No production, schema, test, or fixture file was changed by this review.

## Executive result

The suites do invoke important production seams directly: `parse_elf64`, `_resolve_tool`, `_mapped_closure`, `_seal_source`, `_spawn_helper`, `_stop_helper`, `_prepare`, owner handoff/close, report decoding, and launcher orchestration. The executable-sealing matrix is particularly strong. All seven direct portable routes passed and all seven rejected optimized Python.

They do **not**, however, own every hostile branch required by ADR 0087. The fresh-crash test has no recovery supervisor, report mutations are coupled and the tracked schema is not driven by the hostile corpus, several authority/open/handoff/report-seal/launcher branches are not injected, and the prior parser hostile contract was not ported to the new production parser. Fixture manifests also advertise cases that are deliberately sliced away or never selected. Native jobs are expressly forbidden from filling these portable gaps (`ADR0087:239-250`).

## Findings

### P0

None found.

### P1-1 — The claimed fresh crash/recovery matrix performs a fresh retry, not recovery by a fresh supervisor

**Lines:**

- `test/outcome-two-recovery-portable.py:93-135` replaces every authority-bearing production seam with in-memory mocks; the fake child has no live gate/pidfd/process and the fake descriptors are integers in a Python set.
- `test/outcome-two-recovery-portable.py:184-192` exits the case process at a checkpoint.
- `test/outcome-two-recovery-portable.py:214-224` only observes that subprocess exit.
- `test/outcome-two-recovery-portable.py:232-235` then launches an unrelated successful preparation and labels it “fresh recovery.”
- Production has only `_prepare` and owner-local cleanup (`completion_trusted_runtime_closure.py:1116-1203`); there is no fixed outer crash-supervisor/recovery entry point for the test to drive.

ADR 0087 requires “crash/recovery from a fresh supervisor process with no inherited module state” (`246`) and assigns crash recovery to a fixed outer supervisor. A subsequent clean run proves module-state independence, but it does not discover, authenticate, terminate/reap, or classify resources from the crashed run. Because the crash cases use only fake resources, they do not even prove the OS-owned anonymous-fd/PDEATHSIG half of the recovery contract. This leaves the crash/recovery hostile branch unqualified.

### P1-2 — Report mutations do not independently challenge semantics, and the tracked schema is not run against the golden or hostile corpus

**Lines:**

- `test/outcome-two-runtime-report-portable.py:67-85` changes ordering, dependencies, seal state, and metadata without recomputing the affected per-tool/mapping/top-level digests.
- `test/outcome-two-runtime-report-portable.py:123-125` sends those coupled mutants only to the production semantic decoder.
- `test/outcome-two-runtime-report-portable.py:100-112,137` merely inspects selected schema source fields; it never compiles the schema or validates the golden/mutations with it.
- `scripts/validate-schemas.ts:52-75` gives the schema one unrelated positive sample; the generic negative check only adds one unknown top-level field.
- Production validation at `completion_trusted_runtime_closure.py:1171-1174` calls the same `_validate_report_bytes` implementation twice. It does not validate with the tracked schema or a second independent codec.

For example, `object-order`, `duplicate-needed`, `missing-provider`, `seal-profile`, and `sealed-executable` can all be rejected by stale digest checks even if their intended semantic checks are removed. `tool-order` similarly retains a stale aggregate digest. The suite therefore cannot show independent hostile branch coverage. It also cannot show that `schemas/trusted-runtime-closure-v1.json` accepts the exact canonical fixture and rejects each structural mutation. This misses ADR 0087’s tracked-schema plus independent semantic validation (`168`) and schema-rejection/determinism requirement (`247`).

### P1-3 — Required authentication, ambiguous-map, report-seal, handoff, and launcher fault branches are not driven

**Authentication:** `test/outcome-two-runtime-closure-portable.py:85-124` models only regular fixed paths. It has no symlink, ancestor replacement, stat/open replacement, second-resolution change, or before/during/after short-read scripts for production `_resolve_once`/`_authenticate` (`completion_trusted_runtime_closure.py:317-443`). One final-object generation drift and one short read do not satisfy ADR 0087:242.

**Mappings:** `test/outcome-two-mapped-closure-portable.py:148-167` covers stable/drift/unknown/unopenable/missing/bounds/open exhaustion, but not the declared ambiguous-fingerprint or 129-unique-object cases. ADR 0087:243 explicitly requires ambiguous mapping rejection.

**Report sealing and handoff:** `_seal_report` (`completion_trusted_runtime_closure.py:836-868`) has no portable success/fault adapter matrix for partial write, fsync, readback, `F_ADD_SEALS`, `F_GET_SEALS`, read-only `/proc/self/fd` reopen exhaustion/identity, or close failure. Handoff tests at `test/outcome-two-recovery-portable.py:168-178` inject only checkpoints; they do not fault the three `F_GET_SEALS` calls, report read, ready-baseline proof, or transfer bookkeeping in `completion_trusted_runtime_closure.py:1047-1073`.

**Launcher:** `test/outcome-two-trusted-launcher-portable.py:28-67` scripts only coarse adapter outcomes. Its success values fabricate completed tool outcomes, and `:88-106` fabricates the sandbox result. No portable test drives `_SystemLauncherAdapter` (`completion_trusted_runtime_launcher.py:141-212`), `_run_fixed_tool` (`391-485`), or `_run_fixed_sandbox` (`487-520`) through scripted syscall/process faults. Invalid/duplicate handoffs and second consumption are also absent.

**Every-open-site/partial-init consequence:** descriptor exhaustion is covered for selected authentication, mapping, and helper opens, but not owner baseline opens, report reopening, report memfd setup, handoff revalidation, or launcher pipe/process setup. This is materially short of ADR 0087:245 and cannot be deferred to native jobs (`250`).

### P1-4 — The accepted prior ELF hostile contract still targets the old parser, while the new parser receives only a small subset

**Lines:**

- The prior suite’s header/table matrix is `test/aws-stage2-completion-runtime-closure.py:94-119`, segment/mapping matrix is `121-140`, and interpreter/dynamic/string/name matrix is `142-205`.
- Its TypeScript wrapper invokes `completion_runtime_closure.py`, not `completion_elf.py` (`test/aws-stage2-completion-runtime-closure.test.ts:7-9,12-24`).
- The new parser suite covers five fixture rejects and two mutations only (`test/outcome-two-runtime-closure-portable.py:39-58`).

The old tests therefore provide no regression authority for the new `parse_elf64`. Unported branches include complete header identity/profile mutations, section-table shapes, LOAD overlap and file/memory constraints, duplicate dynamic tags, `DT_FLAGS`/`DT_FLAGS_1`, malformed/unterminated string tables and names, duplicate SONAME, and dynamic termination. Running the old suite successfully does not execute either production call site of the new parser (`completion_trusted_runtime_closure.py:430,783`). ADR 0087 moved the security parser to a new module; its prior hostile contract must follow it rather than remain adjacent evidence.

### P2-1 — Fixture truth is not enforced; manifests contain dead or unimplemented cases

**Lines:**

- `test/outcome-two-runtime-closure-portable.py:160-165` intentionally selects `cases[:10]`, excluding fixture rows `test/fixtures/outcome-two/closure/cases.json:29-30`. `FsOps` does not implement either excluded fault token; separate synthetic bound tests do not establish fixture truth.
- `test/outcome-two-mapped-closure-portable.py:50` loads `maps/cases.json` only for its object lookup. It never iterates `hostile`; rows `test/fixtures/outcome-two/maps/cases.json:13,19` are not implemented by `MapOps` or selected by a test.
- `test/outcome-two-lifecycle-portable.py:198-258` selects four named arrays but never consumes `MATRIX["cleanup"]`; in particular `test/fixtures/outcome-two/lifecycle/faults.json:23` (`unexpected-owned-child`) has no case.

A fixture row can be renamed, deleted, added, or left unimplemented without failing the suite. This conflicts with the requested fixture-truth property and makes the manifests overstate coverage.

### P2-2 — Residue assertions cover only adapter-local fds/children, not all ADR residue domains

**Lines:**

- `test/outcome-two-mapped-closure-portable.py:130-135`, `test/outcome-two-sealing-portable.py:142-154`, and `test/outcome-two-lifecycle-portable.py:198-264` assert fake adapter collections.
- `test/outcome-two-recovery-portable.py:52-64` defines the entire baseline as `{0,1,2} | fake_live` and an always-empty child baseline.
- `test/outcome-two-trusted-launcher-portable.py:88-106` returns prebuilt sandbox cleanup booleans rather than deriving them from an adapter model.

No portable adapter models or asserts tracked file, mount, namespace-handle, or checkout mutation/restoration, despite ADR 0087:248. If those domains are intentionally impossible for this phase, the suite still needs an enforceable no-effect surface assertion; prebuilt `True` fields are not evidence.

### P3

None found.

## Contract coverage summary

| ADR 0087 portable contract | Result at `64c0557` |
| --- | --- |
| Valid closure; missing loader/library; duplicate candidate; unknown interpreter; forbidden tag; object/tool byte bounds | Mostly covered through production `_resolve_tool`; role/SONAME and path-replacement variants are incomplete |
| Owner/mode/generation/short-read/replacement before, during, after authentication | **Partial**; no symlink/ancestor/replacement/phase matrix |
| Stable mapping, drift, unknown/unopenable, missing role/dependency, byte/line bounds | Covered through production `_mapped_closure` |
| Ambiguous mapping and mapping object bound | **Missing/dead fixture rows** |
| Executable seal write/fsync/readback/digest/source/seal/close matrix | Strongly covered through production `_seal_source` |
| Report sealing matrix | **Missing** |
| Descriptor exhaustion at every open site and partial initialization | **Partial** |
| Helper setup/exec/wait/reap and primary-plus-cleanup/fd reuse/double close | Substantial direct coverage; PDEATHSIG/parent-change/dup/status-write and owner-child branches remain incomplete |
| Fresh crash supervisor recovery | **Missing; fresh retry only** |
| Independent deterministic report and mutation checks | Byte stability covered; semantic mutations coupled |
| Tracked schema rejection | **Not driven by portable hostile corpus** |
| No residual fd/child/file/mount/namespace/checkout mutation | Fake fd/child subsets only |
| No real effects | Passed by inspection and observed execution; no sudo/native/mount/network/tool/cloud/workflow action was invoked |
| Optimized rejection | Covered; all seven suites exited nonzero under `python3 -O -I -B` |

## Prior-contract coverage

The prior `test/aws-stage2-completion-runtime-closure.py` remains useful adjacent evidence and passed in ordinary and optimized modes. It targets the frozen Stage 2 parser in `completion_runtime_closure.py`; it does not call the Outcome 2 parser. Consequently it supplies **zero direct branch coverage** for `completion_elf.parse_elf64`. Its hostile parser matrices need to be ported or parameterized against the new API, with intentional behavior differences documented.

## Measured line highs

Counts are gross physical lines from exact predecessor `bec0a19...`. New text files equal their current physical line count. `scripts/validate-schemas.ts` uses its 19-line Outcome 2 gross addition only. Fixture aggregate uses conservative on-disk `wc -l`, including seven LF bytes found inside binary ELF fixtures; `git --numstat` reports 3,805 text additions because binary rows are `-/-`, while the conservative physical subtotal below is 3,812.

| Surface | Measured | ADR high | Margin |
| --- | ---: | ---: | ---: |
| `completion_elf.py` | 240 | 240 | **0** |
| `completion_trusted_runtime_closure.py` | 1,220 | 1,220 | **0** |
| `completion_trusted_runtime_launcher.py` | 599 | 600 | 1 |
| `trusted-runtime-closure-v1.json` | 122 | 230 | 108 |
| `validate-schemas.ts` Outcome 2 addition | 19 | 30 | 11 |
| runtime-closure portable | 195 | 250 | 55 |
| mapped-closure portable | 169 | 240 | 71 |
| sealing portable | 156 | 210 | 54 |
| lifecycle portable | 266 | 290 | 24 |
| recovery portable | 249 | 290 | 41 |
| runtime-report portable | 149 | 230 | 81 |
| trusted-launcher portable | 149 | 280 | 131 |
| TypeScript wrapper | 48 | 120 | 72 |
| `test/fixtures/outcome-two/**` | 231 | 500 | 269 |
| **Trusted/portable subtotal** | **3,812** | **4,730** | **918** |

No high is crossed. The parser and trusted closure owner are exactly at their non-transferable highs; any physical-line growth requires a new ADR. Unused margin elsewhere cannot be transferred to either file.

## Checks run

| Check | Result |
| --- | --- |
| `git rev-parse HEAD` | `64c055762e260b8fc2eed96741bdb30c89183f3c` |
| Seven `python3 -I -B test/outcome-two-*portable.py` routes | **PASS** |
| Seven `python3 -O -I -B ...` rejection checks | **PASS**; each exited 1 |
| `python3 -m compileall` on exact production/portable Python | **PASS**; generated caches removed |
| Fixture JSON parse and canonical JSONL byte check | **PASS** |
| Prior `python3 test/aws-stage2-completion-runtime-closure.py` | **PASS** (adjacent old parser only) |
| Prior parser suite under `python3 -O` | Exited 0; not optimization-safe, but outside the new wrapper’s claimed seven-suite gate |
| `npm test -- --test-name-pattern='Outcome 2 portable hostile suites'` | **NOT RUN / environment blocked:** local `tsx` is absent (`node_modules` not installed) |
| `npm run schemas` | **NOT RUN / environment blocked:** local `tsx` is absent |
| `git diff --check bec0a19...HEAD` | Reports pre-existing trailing whitespace in unrelated capability rereview reports; no finding against reviewed production/tests |
| Working tree after review checks | Clean before this report was added; no cache residue |

## Gate conclusion

This head does not satisfy ADR 0087’s no-unresolved-P0–P3 review gate. Do not treat the portable suite as complete, and do not let native qualification duplicate or paper over these missing portable matrices.
