# Outcome 2 Wave 2 hostile review — launcher and schema

**Disposition:** REJECT — unresolved P0–P2 findings

**Exact reviewed head:** `64c055762e260b8fc2eed96741bdb30c89183f3c`

**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`

**Review-only scope:** accepted ADR 0087, `OUTCOME-TWO-PLAN.md`, `.pi/outcome-two/closure-audit.md`, `.pi/outcome-two/portable-audit.md`, and the exact trusted closure/parser/launcher/schema/portable-test implementation at the reviewed head. No production file was changed.

## Findings

### P0 — authentication occurs after trusted code has already executed and does not authenticate the loaded T1 surface

`deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:141-170` authenticates only the current pathname bytes of `completion_trusted_runtime_closure.py`. The check is not invoked until `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:533-537`, after the caller has already imported the closure and parser, called `prepare_fixed_runtime_closure()`, performed host discovery, spawned helpers, and produced a handoff. The production constructor at `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1212-1214` has no prior source admission.

The check also omits the launcher and `completion_elf.py`, does not prove `/usr/bin/python3` is the process executable, and hashes a fresh pathname read (`launcher.py:166`, `launcher.py:225-238`) rather than the byte generation that Python loaded. A replaced module can execute during import/preparation, be restored before line 166, and pass this check. This violates ADR 0087's requirement that tracked, exact-head-authenticated T1 code execute as fixed `/usr/bin/python3 -I -B` with an authenticated import root before any authority-bearing discovery. Authentication after the side effects cannot make those effects trusted.

### P0 — executable handoff descriptors are not bound to the canonical report before trusted execution

`RuntimeClosureHandoff` is freely constructible from three integers at `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:79-83`. The launcher inspection at `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:175-187` checks only regular-file status, nonzero size, seals, CLOEXEC, and report access mode. After decoding the report at `launcher.py:537`, it immediately executes the gzip and zstd descriptors at `launcher.py:538-539`; it never reads either executable descriptor or compares its size/SHA-256 to that tool's report executable object.

Consequently, any caller that can instantiate the public handoff can supply an arbitrary executable memfd with the expected seals plus an unrelated valid report. The child executes that object in the trusted host environment; producing the fixed output does not prevent filesystem, process, or network side effects. Fixed fd numbers and fixed argv do not authenticate executable authority. This breaks the T1-to-T2 descriptor transition and the requirement that the untrusted phase verify the supplied sealed descriptors against canonical metadata before execution.

### P1 — `launch_fixed_sandbox_probe()` does not launch or own the fixed sandbox boundary

`deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:487-520` only inspects the calling process. The public path at `launcher.py:570-599` does not fork, establish user/PID/mount/network namespaces, construct a chroot/read-only mount set, clear groups/capability sets, lock securebits, set NNP, install seccomp, or register any path/mount/child authority. It instead requires the caller already to be PID 1 and already constrained, then hard-codes all restoration booleans true at `launcher.py:518-520`.

This transfers the security transition to an unspecified external invoker and cannot prove that the fixed launcher created or cleaned the exact Job E boundary. In particular, `paths_restored` and `children_reaped` have no corresponding baseline or cleanup operation. It does not implement ADR 0087's fixed second entry point or its ownership/cleanup contract.

### P1 — report production is not validated by the tracked schema plus an independent codec

At `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1169-1174`, both claimed validations call the same `_validate_report_bytes` implementation. No production path loads or applies `schemas/trusted-runtime-closure-v1.json`. The portable report test only inspects selected schema members at `test/outcome-two-runtime-report-portable.py:100-112`; it does not compile the schema against the golden report and hostile semantic mutations.

The implementations are observably non-equivalent: the closure codec at `completion_trusted_runtime_closure.py:956-963` accepts a slash-free SONAME such as `"bad name"` when dependencies and digests are recomputed, while the tracked schema rejects it under `schemas/trusted-runtime-closure-v1.json:24-29`, and the launcher's independent decoder rejects it at `completion_trusted_runtime_launcher.py:318-323`. Thus two calls to one codec neither satisfy the independent-schema contract nor prove that a sealed producer report is accepted byte-identically by the declared schema and consumer.

### P1 — sealed-report close failure can retry an uncertain descriptor

`deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:858` closes the writable report fd. If that close reports failure, the handler at `closure.py:860-861` passes the same fd to `_close_local`, which closes it again. After a close error, ownership is uncertain; the number may already have been released and reused, especially in a multithreaded process. Retrying can close an unrelated descriptor and violates the exact fd ownership/fd-reuse rule. Report sealing has no direct portable after-effect-close test; `test/outcome-two-sealing-portable.py` exercises `_seal_source`, not `_seal_report`.

### P2 — portable launcher coverage replaces the system boundary with successful scripted claims

The launcher suite supplies a `SimpleNamespace` handoff and a scripted adapter at `test/outcome-two-trusted-launcher-portable.py:70-87`. Sandbox success is a preconstructed all-true result at `launcher-portable.py:88-95`. The only source-authentication assertion is event ordering at `launcher-portable.py:123-129`.

It therefore does not challenge loaded-bytes versus current-path authentication, omitted launcher/parser authentication, executable/report mismatch, public handoff forgery, fd substitution/reuse, real fixed-fd execution, or actual sandbox construction. These are prior-contract branches explicitly required by ADR 0087 and the Wave 1 audits, and the scripted pass masks the P0/P1 gaps above.

### P3

No separate P3 finding.

## Prior contract coverage

| Contract area | Present coverage | Hostile-review result |
| --- | --- | --- |
| Exact launcher/source admission | Isolated/no-bytecode flags, fixed `/usr/bin/git`, current closure-file blob comparison | **Not covered:** admission is post-preparation; loaded launcher/parser/closure generation and fixed Python executable are unauthenticated. |
| Handoff/fd ownership | Distinct fd integers, one-shot marker, reverse close attempts, descriptor-baseline comparison | **Not covered:** public handoff provenance, executable/report binding, substitution/reuse, and uncertain report-fd close. |
| Trusted → untrusted transition | Descriptor seals and CLOEXEC are inspected | **Not covered:** qualification executes before any sandbox transition; Job E transition is external. |
| Fixed execution | Fixed roles, fd targets 198/199/200, payloads, argv, environment, deadline, output marker, close-range code | **Partial only:** portable tests stub execution; executable bytes are unauthenticated and no seccomp/network/filesystem boundary is installed. |
| Schema and semantic codec | Closed Draft 2020-12 schema, fixed tool order, canonical/digest mutations, duplicate-key/framing checks | **Partial only:** actual producer bytes are not schema-validated; producer/schema/consumer semantics diverge. |
| Canonical/sealed report | Sorted compact JSON, one LF, digest recomputation, readback, exact data seals, read-only reopen | **Partial only:** repeated validation is not independent and report close uncertainty can retry ownership. |
| Disclosure | Closed report objects and portable mutations reject added path/environment/address/output/PID fields; golden report has metadata only | **Covered for declared report fields.** This does not cure executable authority or source-admission defects. |
| Cleanup | Portable closure/mapping/sealing/lifecycle/recovery fault suites and launcher reverse-close script | **Partial only:** no fixed sandbox resource owner and no `_seal_report` after-effect close/fd-reuse case. |

## Measured line highs

Gross/current physical lines from exact predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa`:

| Surface | Measured | ADR 0087 high | Margin |
| --- | ---: | ---: | ---: |
| `completion_elf.py` | 240 | 240 | 0 |
| `completion_trusted_runtime_closure.py` | 1,220 | 1,220 | 0 |
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
| TypeScript portable wrapper | 48 | 120 | 72 |
| `test/fixtures/outcome-two/**` aggregate | 231 | 500 | 269 |
| **Trusted/portable measured subtotal** | **3,812** | **4,730** | **918** |

No line high is crossed. The parser and closure are exactly at their non-transferable highs, and the launcher has one line remaining. Fixing these security contracts requires a new ADR before crossing a high, adding a surface, or compressing behavior to evade readable-line accounting.

## Checks

- Exact reviewed head: **PASS** — `git rev-parse HEAD` returned `64c055762e260b8fc2eed96741bdb30c89183f3c` before this report commit.
- Seven direct portable Python suites under `/usr/bin/python3 -I -B`: **PASS**.
- `npx tsx --test test/outcome-two-portable.test.ts`: **PASS** (1/1).
- `npm run schemas`: **PASS** (15 schemas).
- `npm run format:check`: **PASS**.
- `npm run typecheck`: **PASS**.
- Target-surface `git diff --check` from the accounting predecessor: **PASS**.
- Full `npm test`: **FAIL** — 885 passed, 2 failed, 3 skipped of 890. Both failures are out-of-scope `test/dev-launcher-profiles.test.ts` Docker-log fixture failures (`ENOENT` for temporary `docker.log`); the Outcome 2 portable wrapper passed in the same run.
- Native Linux x86_64 closure, real memfd execution, and sandbox Jobs A–E: **NOT RUN** on Darwin arm64; no native authority claimed.

## Review gate

The exact head is not eligible for launcher/schema sign-off. Resolve both P0 findings and all P1/P2 findings, restore independent tracked-schema validation and real hostile boundary coverage, remain within accepted line/surface authority (or adopt a new ADR), and obtain a fresh exact-head hostile review before native execution.
