# Outcome 2 exact-head signoff — source and issuance trust

- Signoff ID: `O2-SIGNOFF-SIGN-TRUST`
- Exact reviewed implementation head: `aa45a043e4eabf29f7f34b7ddb3e8c42af590b0e`
- Governing decision: accepted ADR 0089, with non-conflicting ADR 0088/0087 rules
- Scope: only the final-review findings and corrections concerning bootstrap/source admission, issuer-received descriptor leases, and report/generation binding
- Verdict: **BLOCKED — one P1 and two P2 findings remain. Native Jobs A–E implementation is not ready to begin.**

## Findings

### P1-1 — The corrected launcher corpus still manufactures each typed oracle and sentinel instead of exercising the fixture-selected bootstrap/issuer branch

**Exact symbols:**

- `test/outcome-two-trusted-launcher-portable.py:204-213` — `PrimitiveModel.trip`
- `test/outcome-two-trusted-launcher-portable.py:384-430` — `PrimitiveModel.invoke`
- `test/outcome-two-trusted-launcher-portable.py:435-480` — bootstrap/authenticate/load adapters
- `test/outcome-two-trusted-launcher-portable.py:585-613` — issuer/consumer/bundle adapters

The correction now calls functions bearing the production names, but `trip()` itself appends the fixture's declared sentinel and constructs `RuntimeLauncherError(..., row["intended_code"])`. The selected branch therefore does not determine either oracle.

In the focused families, all `_load_private_closure` cases fail on the first `FaultSources.__getitem__` rather than completing held-byte loading or challenging tracked/checkout imports; `_authenticate_sources` cases fail in the patched `_held_sources` before Git/blob/Python-identity predicates; every `_consume_issuance` case fails before `recvmsg` returns ancillary data; and every `_verify_bundle` case fails in the patched `_inspect_fd` before generation-row validation. Consequently bootstrap, received-rights cleanup, and generation aliases can regress while every row retains its declared code and sentinel.

This is the final-review P1 production-binding finding in a renamed form and still violates ADR 0089 section 7 and `AT-ADAPT-BOOT-01`, `AT-ADAPT-ISSUE-01`, `AT-ISSUE-02`, `AT-ISSUE-03`, and `AT-FIXTURE-01`.

### P2-1 — A malformed ancillary record preceding `SCM_RIGHTS` leaves later received descriptors unleased

**Exact symbol:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:913-940`, `_leased_credentials`.

The function validates ancillary records and creates leases in one ordered loop. If an unknown ancillary record, malformed/duplicate credentials record, or another early error occurs before a later rights record, iteration stops before those kernel-installed descriptor integers are converted to `_FdLease`. The exception cleanup closes only rights already encountered.

A focused no-effect diagnostic supplied an unknown record followed by one rights record. Production rejected with `issuer-ancillary`, made zero close attempts, and the rights fd remained open. The same helper is used for the consumer handoff and issuer/helper acknowledgements, so the final-review received-lease finding is not closed for hostile record order. All returned rights must be registered before semantic validation can abort, with close uncertainty preserved.

### P2-2 — Descriptor aliases are not required to carry one identical authenticated source generation

**Exact symbol:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:583-612`, `_verify_bundle`.

The exact `(tool_index, object_index)` coverage correction is present, but alias consistency at lines 605-610 records only `(size, sha256)` per descriptor index. It does not require aliased rows to have the same `source_generation`. A focused call to the production verifier accepted zstd/gzip loader rows that shared one descriptor and identical report size/digest while carrying different eight-field source generations.

ADR 0089 section 5 requires aliases to name one identical authenticated object. Closure-side construction currently applies a stronger check, but the one-shot issuer and consumer both rely on this weaker launcher verifier, and the fixture's `alias-different-object` row is masked by P1-1 before reaching it. The launcher verifier must reject source-generation alias conflicts directly.

## Focused checks

| Check | Result |
| --- | --- |
| Exact initial head/worktree | **PASS** — `aa45a043e4eabf29f7f34b7ddb3e8c42af590b0e`, clean |
| In-memory compile of parser, closure, and launcher | **PASS** |
| Isolated trusted-launcher portable suite | **PASS, non-accepting under P1-1** |
| Isolated runtime-report portable suite | **PASS** |
| Isolated lifecycle portable suite | **PASS** |
| Unknown-before-rights lease diagnostic | **FAIL contract** — rejected packet retained the received fd with no close attempt |
| Divergent alias-generation diagnostic | **FAIL contract** — `_verify_bundle` accepted the conflict |
| TypeScript/AJV wrapper | **NOT RUN / environment blocked** — `node_modules/.bin/tsx` is absent |
| Native/privileged Jobs A–E | **NOT RUN and not authorized** |

## Exact implementation binding

| Surface | Git blob | SHA-256 |
| --- | --- | --- |
| launcher | `e340f65a7acdbdac0e4bf498e9d94f53d221dd61` | `3b8a3481c0f42624c1b2b07e558c1c2e6352d580b8030554f169df32d4210ff6` |
| closure | `2f952273625e07bfb167ebfd9771ba1568ddd46f` | `92da735611bb2e0eb00d426f31505e8e60f47df88c9707c62f87da866c288be5` |
| trusted-launcher portable | `8b7bd3e0d09792b422464d5c5cf35c0b08573864` | `9b2dd56f72066ad691d8d07bd46c7589c5e0c74b2843a411205e312400b7fef6` |
| runtime-report portable | `104e530eb5aa90eaa0dbeaf74b7f9e3c61a22cc8` | `786982ec7157e7d51e8d6e90b2958326f752a95f4a65df12a7ebe7676d0fbd22` |

## Native implementation readiness

**NOT READY.** ADR 0089 requires zero unresolved P0–P3 at a fresh exact head. Replace fixture-selected error/sentinel injection with primitive faults that reach the named production branches, lease every returned rights descriptor before ancillary validation can abort, and require aliased rows to carry one identical authenticated source generation. Then obtain another exact-head signoff before native Jobs A–E implementation.

SIGNOFF COMPLETE
