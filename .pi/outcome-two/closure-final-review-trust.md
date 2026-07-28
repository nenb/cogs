# Outcome 2 final exact-head trusted-closure hostile review

- Review ID: `O2-FINAL-R-TRUST`
- Exact reviewed implementation head: `3135c16add3abe1b32785f3d577cccd811ce5e54`
- Governing decision: accepted ADR 0089, with non-conflicting ADR 0088/0087 rules
- Acceptance gate: `.pi/outcome-two/closure-second-correction-gate.md`
- Review mode: review only; no production, schema, fixture, test, workflow, native, privileged, provider, cloud, AWS, or deployment action or edit
- Verdict: **BLOCKED — one P0, two P1, and one P2 finding remain. No P3 finding was established. Native implementation is not ready to begin.**

All five first closure reviews, all five second closure rereviews, and the second-correction acceptance gate were read in full. The exact production symbols—not fixture labels—were inspected and statically challenged.

## Findings

### P0-1 — The qualification result still promotes partial policy observations to exhaustive capability and acquisition facts

**Exact symbols:**

- `completion_trusted_runtime_launcher._SystemOps.capget_zero` and `.drop_bounding` at `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:604-623`
- `completion_trusted_runtime_launcher._SystemOps.probe_seccomp_denials` at `:657-675`
- `completion_trusted_runtime_launcher._run_tool_with_ops` at `:1492-1510`
- `completion_trusted_runtime_launcher._coordinate_with_ops` at `:1671-1685`

ADR 0089 requires independent observations for effective, permitted, inheritable, bounding, and ambient capability sets, and permits `no_acquisition_route` only when every route in the accepted exhaustive x86-64 table is observed denied or removed. Production reads only the three `capget` sets. It attempts bounding drops and ambient clearing but never rereads either set. It then probes only four syscall denials (`execve`, `socket`, `memfd_create`, and `seccomp`) and publishes `capabilities_zero`, `seccomp_denials_exact`, and `no_acquisition_route` as true.

The production denial table itself contains only seven socket-family rows (`socket`, `connect`, `accept`, `bind`, `listen`, `socketpair`, and `accept4`). The accepted socket-route inventory remains open for `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `shutdown`, `getsockname`, `getpeername`, `setsockopt`, `getsockopt`, `recvmmsg`, and `sendmmsg`. The cBPF also admits every `execveat` argument shape rather than checking the fixed fd/flags shape required by ADR 0089; the later authority-absence checks do not make the policy itself exact.

A successful result can therefore make authoritative security claims from operation success and four representative probes rather than the required complete observations. This is the prior trusted-result overclaim in a narrower implementation shape.

### P1-1 — The launcher and recovery ledgers still certify labels without executing their named production state machines

**Exact symbols and tests:**

- `test/outcome-two-trusted-launcher-portable.py:47-93` resolves each `production_method` only far enough to check `callable(...)`.
- `test/outcome-two-trusted-launcher-portable.py:435-453` adds every row to `consumed`, `oracle`, and `sentinel` sets without invoking its named method or checking its `primitive_fault`/`intended_code`.
- `test/outcome-two-recovery-portable.py:38-74,277-285` does the same for every non-crash recovery row.

A focused AST call probe confirmed that the trusted-launcher suite does not call the exact production `_bootstrap_with_ops`, `_authenticate_sources`, `_load_private_closure`, `_coordinate_with_ops`, `_run_tool_with_ops`, `_recover_transaction_with_ops`, `_consume_issuance`, or `_verify_bundle` symbols. It directly challenges only narrow helpers such as `_credentials`, `_descriptor_snapshot`, `_enter_boundary`, `_SourceAdmission._consume`, and `_WorkerIssuer._consume_runtime_closure_capability`.

Consequently:

- held-byte loading and opaque admission cases `AT-ADM-02/03` are labels, not executions of the bootstrap/loader;
- `AT-ADAPT-ISSUE-01`, exact `SCM_RIGHTS` packet/ack/EOF behavior, generation-row equality, and executable/report descriptor binding never drive `_WorkerIssuer._accept_runtime_closure`, `_consume_issuance`, or `_verify_bundle`;
- exec-ready, final-map, root, T2 observation, lifecycle, and unavailable families do not enter the production coordinator; and
- family-wide `intended_code` labels such as `issuer-cardinality` are not compared with the exact production codes such as `issuer-credentials-cardinality` and `issuer-rights-cardinality`.

This directly violates ADR 0089 section 7 (including line 138's fixture rule) and the incorporated `AT-ADAPT-*`/`AT-FIXTURE-01` gate. The seven direct suites being green does not close the gate and explains why P0-1 remains undetected.

### P1-2 — Namespace/root authority still begins before outer registration and partial root creation is not recoverable

**Exact symbols:**

- `completion_trusted_runtime_launcher._run_tool_with_ops` forks the namespace owner at `:1415-1420` and registers it only at `:1426`, with no release gate.
- `completion_trusted_runtime_launcher._namespace_owner` assigns `root` only after `_materialize_root` returns at `:1227` and skips root cleanup when that call fails after create/mount/copy at `:1289-1294`.
- Its cleanup suppresses child/root failures at `:1284-1294` and converts the transaction to generic exit 125.
- `_run_tool_with_ops` still performs raw descriptor closes and a best-effort grandchild `waitpid(..., WNOHANG)` at `:1515-1542` rather than transferring exact authority to the surviving owner.

ADR 0089 requires write-ahead root/mount intent and requires every namespace owner and PID-1 child to remain behind a release gate until the surviving outer owner has registered process, descriptor, root, mount, and namespace authority. A failure inside `_materialize_root` can leave the named `/run/cogs-o2-runtime-v1` directory after the private mount namespace disappears, while the outer process never received authority to identify or remove that exact state. The current process topology also leaves the outer owner trusting inner status rather than owning/reaping the PID-1 descendant transaction. Native lifecycle Jobs cannot repair this production ownership gap.

### P2-1 — Received issuance descriptors bypass the mandatory lease/close-uncertainty state machine

**Exact symbol:** `completion_trusted_runtime_launcher._consume_issuance` at `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1034-1075`.

`recvmsg(..., MSG_CMSG_CLOEXEC)` returns raw descriptor integers. On credential/truncation rejection they are closed directly at `:1041-1042`; on every later packet/schema/report/row/ack/EOF failure they are directly closed at `:1070-1075`, with close errors suppressed. `_FdLease` ownership is created only after `_consume_issuance` successfully returns (`_coordinate_with_ops:1647-1650`). Thus before/after-effect close faults cannot become `CLOSE_UNCERTAIN`, ordered cleanup failures are lost, and the exact received authority is outside the transaction owner during the most hostile packet-validation cuts. This violates ADR 0089's every-descriptor lease rule and is not exercised by the launcher suite under P1-1.

## Exact implementation binding

| Surface | Git blob | SHA-256 |
| --- | --- | --- |
| `completion_elf.py` | `96ac375a1374fb2d3126378fff952babb3f6f7d8` | `d23e01a31fe1da9b5298fe2be7cefe0c7c581409b2d0947f8bc64ec1e78ffedb` |
| `completion_trusted_runtime_closure.py` | `b2fcda4ceec36a3c149728e770a9589a4a24fa6c` | `b188e1b94441e9bea7a2d11d53481f55eeea0852eaf80bd0b681a50bd41ae249` |
| `completion_trusted_runtime_launcher.py` | `1f7be4038b10cc5df9ef15e54bc302f343e98ee0` | `4fac433c84e1799656b896569a6eb331a040279631a84d1ed8fd228c9a59443b` |
| `trusted-runtime-closure-v1.json` | `10d566ed3ea2d975e78331a425ff93f7f458b4dc` | `fb983f4e64dc90028693b2e8d89faacd33e0b348666a1a7ed4256f106df03611` |
| trusted-launcher portable | `bba6ee57f52d66c26783a10ac0f138b74116ba20` | `77170736ee52d4b849e7d51ea0caf6a67cf646d9f37bd8b9572d2349b4afba9d` |
| runtime-report portable | `1da48a360aa3f3169e60c0016aaf3a17d8ac49e9` | `7fee1e958ada72062eb914ecbe0f53fe580846e2a1ea4122c0f4e049537eacb2` |

## Focused verification disposition

- **Held-byte/bootstrap implementation:** fixed source-set/blob authentication, fixed-Python object identity, checkout-search removal, synthetic parser/closure modules, live endpoint topology, exact admission object/package/worker checks, and ambient public-constructor rejection are present in production shape. No separate production bypass was established. P1-1 prevents hostile acceptance sign-off because the exact bootstrap/loader is not driven.
- **Issuer implementation:** production contains `SO_PASSCRED`, exact PID/UID/GID parsing, one credentials record, one rights record, nonce, acknowledgement, EOF checks, exact report/descriptor bytes, one-shot issuer state, and exact row-position checks. P1-1 and P2-1 prevent protocol/cleanup sign-off.
- **Report/codecs:** the focused report suite entered `_construct_report`, the tracked-schema gate, `_producer_decode_report`/`_producer_reencode_report`, and launcher `_decode_report`/consumer re-encoding. Golden construction and recomputed hostile mutations passed through three distinct production code objects. No separate report-codec finding was established. End-to-end executable/report/generation issuance remains unaccepted under P1-1.

## Focused checks

| Check | Result |
| --- | --- |
| Exact pre-report head/worktree | **PASS** — `3135c16add3abe1b32785f3d577cccd811ce5e54`, clean |
| Seven direct `/usr/bin/python3 -I -B` portable suites under fixed minimal environment | **PASS** |
| Production in-memory compile for parser/closure/launcher | **PASS** |
| Exact production-symbol AST call probe | **FAIL gate** — eight named bootstrap/issuer/T2 symbols are not called by the launcher suite (P1-1) |
| Seccomp table/probe static extraction | **FAIL contract** — 11 accepted socket routes absent; only four denial outcomes probed (P0-1) |
| `git diff --check d111eac..3135c16` and exact-head commit | **PASS** |
| `git fsck --no-progress --no-dangling` | **PASS** |
| TypeScript wrapper/AJV | **NOT RUN / environment blocked** — locked `node_modules/.bin/tsx` is absent |
| Native Jobs A–E / thin integration | **NOT RUN and not authorized** |

All ADR 0089 measured highs remain numeric-green: parser 306/320, closure 2,078/2,100, launcher 1,889/1,900, schema 134/260, registration 27/30, Python suites 350/350, 256/300, 265/300, 538/550, 308/550, 326/400, 471/800, wrapper 155/170, fixtures 680/900, and trusted/portable subtotal 7,783/8,930. Numeric compliance does not cure the findings.

## Native implementation readiness

**NOT READY.** ADR 0089 requires zero unresolved P0–P3 at a fresh exact head. Correct the observed-fact/policy overclaim, make every incorporated launcher/recovery row drive its exact production state machine and typed code, restore write-ahead process/root ownership, and lease received issuance descriptors before native Jobs A–E implementation begins. Thin integration remains later and separately gated.

O2-FINAL-R-TRUST COMPLETE
