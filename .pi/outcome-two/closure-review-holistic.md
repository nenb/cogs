# Outcome 2 Wave 2 holistic hostile review

**Disposition:** **NOT READY** to begin native Jobs A–E  
**Exact reviewed head:** `64c055762e260b8fc2eed96741bdb30c89183f3c`  
**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`  
**Review scope:** accepted ADR 0087, `OUTCOME-TWO-PLAN.md`, `.pi/outcome-two/{closure-audit,portable-audit}.md`, and the exact trusted-closure/parser/launcher/schema/portable-fixture implementation at the reviewed head. Review only; no production or test file was changed.

## Executive decision

The parser, host-object resolver, map fixture validator, descriptor-direct executable sealing, canonical report codec, and local cleanup fault adapters are substantial improvements over the abandoned candidate monolith. They close many Wave 1 unit-level gaps.

They do not establish the accepted T0/T1/T2 boundary. The trusted implementation is admitted only after it has already discovered and sealed host authority; the handoff is forgeable and substitutable; and the public integration launcher executes the handed executable in the ambient host rather than constructing T2. Crash "recovery" is a fresh unrelated success, not recovery by an outer owner. Job E's production probe also asserts more than it measures.

Native runs cannot repair these production contract defects. Starting A–E now would either qualify the wrong APIs or encourage native harness code to absorb missing production security behavior. Resolve all findings and adopt new line authority before native work.

## Findings

### P0-1 — Trusted source admission occurs after all authority-bearing T1 effects

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:20` imports `completion_elf` from ambient import resolution.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1116-1185` resolves host objects, reads procfs, starts helpers, seals executables, and publishes the report.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1212-1214` exposes that work directly without checking isolated/no-bytecode Python, the fixed import root, or tracked source identity.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:141-170` authenticates only the closure module, not the parser or launcher.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:533-537` performs that authentication only after a handoff already exists.

ADR 0087 requires exact-head-authenticated tracked code, fixed `/usr/bin/python3 -I -B`, an empty fixed environment, and an authenticated import root before host discovery. Here an ambiently resolved parser and unauthenticated closure have already created authority before the launcher checks one file. Authenticating later cannot make earlier effects trusted.

**Required direction:** use a fixed authenticated bootstrap before any production module import/effect; bind the parser, closure, and launcher blobs/import root to the same reviewed revision. Do not delegate this missing boundary to native workflow YAML.

### P0-2 — The launcher is a confused deputy for caller-selected executable descriptors

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:79-83` provides a publicly constructible handoff containing only raw fd integers.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1064-1068` transfers those integers without an unforgeable issuance binding.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:147-148` authenticates only the Python type name/module.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:175-187` checks generic file/seal/CLOEXEC properties but never hashes gzip/zstd or compares their bytes, size, mode, and identity to the matching report object.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:352-359` accepts any object exposing three integer attributes.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:421-428,535-539` installs and executes the supplied fds.

A caller can construct `RuntimeClosureHandoff` directly, or close/reuse an fd after legitimate settlement, and supply an attacker-created sealed executable that emits the fixed payload while retaining an unrelated valid report. Exact seals do not prove provenance. The launcher then executes that fd as trusted authority.

**Required direction:** make settlement and consumption one ownership-preserving operation or use an unforgeable, one-shot issuer binding; at consumption, hash and fully inspect each executable fd and bind it to the exact report record before exec. Prove fd close/reuse substitution fails.

### P0-3 — The public qualification launcher never constructs or enters T2

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:391-428` forks, sets only PDEATHSIG/fds, and directly `execveat`s gzip/zstd.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:436-467` releases fixed input in that ambient process.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:487-520` only inspects the caller's current process; it constructs no namespace, chroot, mount, capability, NNP, or seccomp boundary.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:594-599` exposes these two incomplete paths as the accepted public API.

The tool children retain the caller's namespaces, root filesystem, capabilities, and network policy. Dynamic loader/libraries are reopened from the ambient host at exec and are not rebound to the report at this execution. `launch_fixed_sandbox_probe()` is an assertion helper, not a launcher. Therefore the accepted thin integration does not exist and the workload is not behind T2.

**Required direction:** the fixed production owner must construct the accepted read-only sandbox and irreversible privilege/seccomp transition before releasing bytes, while preserving exact loader/library generations. Job E may qualify that production mechanism but may not implement it in a test or workflow.

### P1-1 — Crash recovery has no production owner and is impossible to prove from the current API

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1028-1041` keeps all ownership only in process memory.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1075-1092` can clean only while that owner process remains alive.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1141-1158,1187-1203` records a helper locally and reports residue after failure, but defines no fixed outer supervisor, durable identity handoff, or fresh-process recovery API.
- `test/outcome-two-recovery-portable.py:184-192,214-235` uses `os._exit(73)`, discards the crashed process, then labels a new independent success as recovery.

PDEATHSIG can request child death; it cannot prove exact descendant identity, delivery, or reap after the owning parent has disappeared. The fresh process neither reads nor recovers any prior state. This does not satisfy ADR 0087's outer-supervisor recovery or the Wave 1 portable crash/recovery gap.

**Required direction:** define and test the real outer-supervisor ownership protocol, including pre-registration, parent-death cuts with a real child, exact revalidation/reap, and a terminal uncertainty result when recovery cannot be proved.

### P1-2 — Launcher process cleanup proves only the direct PID, not the accepted lifecycle contract

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:401-428` creates no owned session/process group, pidfd, start-time identity, or descendant baseline.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:464-467` treats direct `waitpid` as complete child cleanup.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:477-482` signals by PID and never checks descendants.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:540-545` turns two direct-child booleans into `children_reaped=true`.

This cannot reject or recover an unexpected descendant and cannot establish the exact no-child baseline required by the plan. It compounds P0-2: a substituted executable can fork residue and still satisfy the fixed-output path.

### P1-3 — Job E's production probe overclaims the sandbox facts it observes

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:487-520`.

The probe checks PID 1, supplementary groups, capget's effective/permitted/inheritable words, NNP/selected securebits, three syscall denials, fds only through 8192, and read-only `/`. It does not prove bounding or ambient capabilities, exact user/PID/mount/network namespaces, checkout read-only/unchanged state, the complete inherited fd set, seccomp replacement denial, acquisition absence, mount ownership, or cleanup. It nevertheless returns every result/cleanup boolean true at lines 518-520. This API cannot back accepted Job E.

### P2-1 — The tracked schema is not part of runtime report validation

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:914-1008` implements one semantic decoder.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1171-1174` invokes that same decoder twice and calls the result independent validation.
- `test/outcome-two-runtime-report-portable.py:100-112,115-139` inspects selected schema text but never validates the golden/hostile reports with the schema.

ADR 0087 requires tracked-schema validation plus an independent semantic codec. Repeating the same function is not independence. The local semantic decoder is also weaker than the schema for SONAME characters/length and `needed` cardinality (`closure.py:956-963`). The global schema command compiles a separate sample, but production never consumes that result.

### P2-2 — Portable launcher coverage mocks every security-sensitive system operation

**Lines:**

- `test/outcome-two-trusted-launcher-portable.py:123-139` verifies scripted event order and a substring check only.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:96-138` supplies the scripted adapter used by those tests.

No portable test drives system descriptor inspection, executable/report digest binding, fd substitution/reuse, process-group/descendant cleanup, actual close-range construction, sandbox fact parsing, or the public source-authentication implementation. The suite therefore passed while P0-2 and P0-3 remained reachable.

### P2-3 — Required aggregate and path/report hostile branches remain uncovered

**Lines:**

- `test/outcome-two-runtime-closure-portable.py:160-165` silently runs only the first ten fixture cases.
- `test/outcome-two-runtime-closure-portable.py:175-189` tests per-tool object/byte bounds through patched internals, not the deduplicated three-tool aggregate at `closure.py:1133-1137`.
- `test/outcome-two-runtime-closure-portable.py:82-149` models directories and regular files but no symlink-component chain/replacement behavior for the complex resolver at `closure.py:317-406`.
- `_seal_report` at `closure.py:836-862` has no direct partial-write/fsync/readback/seal/reopen/close fault matrix; recovery tests patch it out.

These are explicit prior-contract branches, not native responsibilities.

### P2-4 — The sandbox syscall implementation lacks its own Linux x86-64 gate

**Lines:**

- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:362-386` hard-codes x86-64 syscall numbers for `close_range` and `execveat`.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:392-393` gates the tool route to Linux x86-64.
- `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:487-507` uses hard-coded x86-64 `capget`, socket, unshare, and io_uring numbers without the equivalent gate.

The accepted native target may deliberately be Linux x86-64, but unsupported platforms must fail before invoking architecture-dependent syscall numbers. Job workflows must also gate the exact architecture/kernel primitives; they must not infer availability from the portable suite.

### P2-5 — Numeric highs were met partly by compressed security control flow

Examples include `completion_trusted_runtime_launcher.py:420-430,455-463,473-482`, where multiple fallible fd operations and exception branches share physical lines. ADR 0087 explicitly forbids crossing a high by compressing readable control flow. This is especially material because the launcher is at 599/600 and the closure/parser have no remaining lines. Numeric compliance is not a clean readability signoff.

### P3

No additional isolated P3 is recorded. The remaining issues are contract/security blockers or material coverage defects and are classified above.

## Prior Wave 1 contract coverage

| Contract area | Status at reviewed head | Evidence and remaining gap |
|---|---|---|
| Strict ELF64 parser | **Strong partial** | Typed byte-only parser and hostile synthetic fixtures cover malformed/truncated/interpreter/tag/dependency/table cases. Real-host compatibility remains native A scope. |
| Fixed path/object authentication | **Partial** | Root owner/mode, complete read, generation drift, missing objects, SONAME ambiguity, and held-fd source use are covered. Symlink-component and full three-tool aggregate tests remain absent; trusted source admission is P0-1. |
| Mapped closure | **Strong portable unit coverage** | Stable/drift/unknown/unopenable/missing-role/map bounds and descriptor cuts drive `_mapped_closure`. Composition with a genuinely spawned minimal helper remains native A, after P0/P1 correction. |
| Executable sealing | **Strong portable unit coverage** | Held-source-fd copy, partial I/O, generation, readback, seal bits, and cleanup are covered. Report sealing and handoff substitution are not. |
| Descriptor/helper lifecycle | **Partial** | Authentication/helper setup/stop/close aggregation adapters are broad. Launcher descendants, outer recovery, and actual production baseline composition are not proved. |
| Crash/recovery | **Not covered** | Crash termination plus unrelated fresh success is not recovery; no production supervisor exists. |
| Report/schema/determinism | **Partial** | Canonical encoding, duplicate keys, digest mutations, ordering, prohibited fields, and independent-process byte stability are good. Runtime schema validation is absent. |
| Fixed launcher/thin integration | **Not covered** | Scripted ordering/cleanup passes, but executable provenance and T2 construction are absent. |
| No residual fd/child/path/mount/namespace/checkout state | **Not covered holistically** | Local fake registries cover subsets. There is no composed production owner that can make the full claim. |

## Line-high accounting

Gross physical-line additions are measured from ADR 0087's exact predecessor. Binary ELF fixtures are listed separately rather than hidden in a text-line total.

| Surface | Gross lines | High | Margin |
|---|---:|---:|---:|
| `completion_elf.py` | 240 | 240 | **0** |
| `completion_trusted_runtime_closure.py` | 1,220 | 1,220 | **0** |
| `completion_trusted_runtime_launcher.py` | 599 | 600 | **1** |
| `trusted-runtime-closure-v1.json` | 122 | 230 | 108 |
| `validate-schemas.ts` registration | 19 | 30 | 11 |
| runtime-closure portable | 195 | 250 | 55 |
| mapped-closure portable | 169 | 240 | 71 |
| sealing portable | 156 | 210 | 54 |
| lifecycle portable | 266 | 290 | 24 |
| recovery portable | 249 | 290 | 41 |
| runtime-report portable | 149 | 230 | 81 |
| trusted-launcher portable | 149 | 280 | 131 |
| TS portable wrapper | 48 | 120 | 72 |
| fixture text additions | 224 | 500 aggregate | 276 before binary treatment |
| binary fixtures | 9 files (eight 1,024-byte ELF files and one 511-byte ELF file) | same fixture aggregate | explicitly disclosed |
| **Countable trusted/portable text subtotal** | **3,805** | **4,730** | **925** |

The aggregate is numerically below its high, but per-file highs are non-transferable. Parser and closure are exactly exhausted and launcher has one line. The required security corrections cannot be made under current per-file authority. Adopt a new ADR/high before changing these surfaces; do not compress further or move production behavior into tests/workflow/schema.

No native-qualification scripts, native report schema, native tests, thin-integration driver, or Outcome 2 CI jobs exist at this head. That absence is expected for this review gate and supplies no native line credit.

## Checks

Review host: Darwin 24.6.0 arm64; no native Linux primitive, cloud, KVM, provider, or workflow execution was attempted.

- `git rev-parse HEAD` — **PASS**, exact reviewed head confirmed.
- Initial and final `git status --short` — **PASS**, clean (ignored `node_modules` excluded); no production/test edits.
- `git diff --check 1cdef21..64c0557` — **PASS** for the Wave 2 implementation range. The broader accounting-predecessor diff reports historical trailing whitespace in unrelated capability review reports, not these implementation surfaces.
- `python3 -m py_compile` for parser/closure/launcher — **PASS**; generated `__pycache__` removed.
- `npx tsx --test test/outcome-two-portable.test.ts` — **PASS**, 1/1 wrapper; all seven Python suites and optimization rejection passed.
- `npm run format:check` — **PASS** as the first stage of `npm run check`.
- `npm run typecheck` — **PASS** as the second stage of `npm run check`.
- `npm run schemas` — **PASS**, 15 schemas plus examples/negative semantics.
- `npm run presets:check`, `egress-bindings:check`, `images:check`, `lock:check`, `licenses`, `audit` — **PASS**.
- Full `npm run check` — **FAIL**, because `npm test` had 885 pass, 2 fail, 3 skipped. Both failures are pre-existing/unrelated `test/dev-launcher-profiles.test.ts` cases (`insecure driver isolates docker tool state...` and `...preflights stale docker resources...`) that expected a temporary `docker.log` on this Darwin host. Focused rerun reproduced exactly those two failures (12 pass, 2 fail). The Outcome 2 portable test passed inside the full run.

## Readiness gate

**Do not begin native Jobs A–E.** First:

1. establish pre-effect exact-source/import admission;
2. remove forged/substitutable handoff authority and bind executable fds to report bytes;
3. implement the actual T2 launcher and exact execution-time loader/library binding;
4. implement recoverable outer process ownership and descendant cleanup;
5. correct Job E's measured contract;
6. add the missing portable hostile coverage and runtime schema independence; and
7. accept revised readable line highs.

After those changes receive a clean exact-head hostile review with no unresolved P0–P3, native A–E may begin in parallel. Thin integration remains after same-head A–E success.
