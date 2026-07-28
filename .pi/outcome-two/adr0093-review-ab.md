# ADR 0093 exact-head hostile review — production API and Jobs A/B

- **Reviewed implementation head:** `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`
- **Scope:** actual A/B production owner and source/client authority, exact A mapping evidence, B parser/top-closure/mask-63/fixed-output evidence, secondary pidfd cleanup, and causal portable acceptance
- **Method:** fresh static review plus portable mocked tests only
- **Native/cloud execution:** **not performed**. No workflow dispatch/rerun, `--workflow-bound` client, sudo, namespace, mount, seccomp, `map_files`, compression executable, provider, network acquisition, cloud, or AWS action was invoked.
- **Verdict:** **BLOCKED**

## P0

No P0 finding.

## P1 findings

### P1-1 — Common calls the deleted ambient API, so no actual A/B production operation can reach the fixed bootstrap

ADR 0093 removed ambient `invoke_fixed_admitted_operation` authority and made the fixed launcher bootstrap CLI the sole operation issuer. The launcher correctly no longer defines `invoke_fixed_admitted_operation` or `_run_held_python_with_ops`; its only production CLI entry is `_bootstrap_main()` (`deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:3450-3514`).

The actual common owner was not migrated. After holding and Git-authenticating the exact source/client bytes, `SystemCommonOps.run_fixed_operation()` still compiles the launcher as an ambient module and performs:

```python
invoke = getattr(module, "invoke_fixed_admitted_operation")
result = invoke(operation, context.head_sha, admitted_bytes, held[client_path].raw, digest)
```

at `scripts/native-qualification/common.py:436-441`. That attribute is absent at exact head. Every A/B workflow client therefore fails with `AttributeError` before either `_bootstrap_with_ops()`, A's mapping owner, or B's compression owner is entered. There is no common-side construction of the sealed held-source/client capsule, no fixed `/usr/bin/python3 -I -B` child with descriptors 0–4, and no result decoding from bootstrap stdout.

This is fail-closed, not a forged pass, but it leaves the real production API nonfunctional and violates ADR 0093 section 1 and the replacement launcher API note. Directly invoking private A/B owners in portable tests cannot supply production reachability or authority.

### P1-2 — Launcher secondary-pidfd failure still loses exact child/reap ownership

`_SystemOps.clone_pidfd()` can observe a positive clone result and a negative returned pidfd, then raises `RuntimeLauncherUnavailable("clone3-pidfd")` (`completion_trusted_runtime_launcher.py:430-435`). `_ProcessOwner.spawn()` has preregistered only a placeholder lease with `pid == 0`; because the call raises, it never records the returned PID (`:787-808`). Cleanup consequently treats that placeholder as already reaped after closing the gates and has no exact `waitpid`/pidfd authority for the child.

This affects B's worker, namespace owner, and tool-child creation paths. Closing the gate may make the child exit, but it does not reap or prove restoration of the exact created process. The closure owner has an explicit bounded direct-child reap for malformed atomic results; the launcher owner does not. This violates ADR 0093 section 5's creator-owned gated cleanup requirement for secondary pidfd failure.

The purported portable secondary-pidfd row does not model this cut: `ProductionLifecycleKernel.clone_pidfd()` raises before allocating a process (`test/outcome-two-lifecycle-portable.py:940-950`). It therefore proves cleanup of “no child created,” not cleanup after `pid > 0` with unusable pidfd authority.

### P1-3 — A/B portable acceptance is not causal over the actual production/authentication paths

The green portable suites structurally cannot detect P1-1 or P1-2:

- `test/outcome-two-trusted-launcher-portable.py:2183-2197` makes the removed ambient route and held-process corpus conditional. It does not require an actual replacement common-to-bootstrap route, and skips the entire outer-process fixture when `_run_held_python_with_ops` is absent.
- `test/outcome-two-recovery-portable.py:681-687` replaces `SystemCommonOps.run_fixed_operation()` with a local adapter returning a completed result. The result is separately fabricated by directly driving the launcher owner (`:893-895`), so common source admission/issuer/bootstrap/result decoding is never composed.
- A's complete-owner ledger contains one success row only. `mapping_owner_success()` directly calls `_qualify_fixed_python_mapping_with_ops()` with a test admission (`test/outcome-two-mapped-closure-portable.py:459-493`); isolated mapping/parser/helper branch tests do not drive complete A production cuts through the missing issuer/bootstrap path.
- B's “production” contract directly calls `_launch_admitted_fixed_runtime_qualification()` and `_launch_admitted_fixed_compression_qualification()` with a test-created `_SourceAdmission` and modeled closure module (`test/outcome-two-trusted-launcher-portable.py:2061-2098`). It is happy-path only and does not select bootstrap mode/authentication, tool-transfer send/receive/EOF/ack failures, or the positive-PID/invalid-pidfd cut.
- Several declared/selected/consumed/oracle sets are populated unconditionally after those substitutions rather than being tied to the actual source-admission and selected primitive event.

ADR 0093 section 10 requires complete A/B production state machines above mocked native primitives and causal equality of declared, selected, consumed, and oracle-proved cases. The current gates accept disconnected private-owner success and completed-result substitution, masking both production defects above.

## P2

No additional P2 finding separate from the blocking P1 findings.

## P3

No additional P3 finding separate from the blocking P1 findings.

## Verified positive properties

- Once entered directly, A's closure-owned transaction resolves fixed Python, registers the helper before release, performs repeated stable `/proc/<pid>/maps` and `map_files` generation checks, requires the exact ordered executable/loader/library mapping sequence, recomputes closure/mapping digests, and closes/reaps before result construction.
- B's direct owner retains the parser observation and independently binds parser closure, zstd/gzip per-tool closures and mappings, and the parser/zstd/gzip top-level aggregate. Launcher/common decoding preserves that relationship.
- B compares produced bytes with `b"cogs-runtime-qualification-v1\n"` before hashing, and producer/decoder/common/schema retain exact seal mask `63` and marker SHA-256 `6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8`.
- The normal B tool-child handoff transfers the creator-held atomic pidfd with credential/case/role/identity binding, registers the received descriptor without a secondary `pidfd_open`, verifies stable identity census and EOF, and acknowledges before creator release (`completion_trusted_runtime_launcher.py:838-914`, `:1447-1486`).
- Common now caches admitted workflow/common/driver/schema identities and schema bytes for later report validation rather than rereading them after effects.
- Relevant gross additions remain within ADR 0093 highs: closure `2811/3100`, launcher `3523/4700`, common `1771/1900`, mapped portable `548/700`, recovery portable `947/1500`, trusted-launcher portable `2219/2300`, A client/test `94/420` and `88/350`, B client/test `94/500` and `85/350`.

## Portable/static verification

- Exact clean head before review: **PASS** — `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a`.
- Python compile for closure, launcher, common, A, and B: **PASS**.
- `test/outcome-two-mapped-closure-portable.py`: **PASS**, non-accepting for complete production/auth fault coverage under P1-3.
- `test/outcome-two-trusted-launcher-portable.py`: **PASS**, non-accepting under P1-3.
- `test/outcome-two-recovery-portable.py`: **PASS**, non-accepting under P1-3.
- Focused TypeScript tests: **not run** because locked `node_modules/.bin/tsx` is absent; no installation or network acquisition was attempted.
- `git diff --check ce1f6f8^..0db8c26`: **PASS**.
- Exact-head identities recomputed for review: launcher SHA-256 `987d6080aad83c18783898df9338bd84febe165cf46912847d027c8eeb24852e`, launcher Git-blob SHA-1 `e5d27b13a4a514f80e6e0b20c6ce3e12d36b32fe`, four-source framed SHA-256 `dde990d2e7adde92be4ef63b1e72042cfdb64232a73a4361863c7ceae68935bc`.

## Signoff

**BLOCKED.** Exact head `0db8c2689ad5a5ffe2ea1b28b4cd814dd45dc27a` has three unresolved P1 findings. It does not qualify for ADR 0093 A/B signoff, native execution authority, workflow dispatch/rerun, artifact reliance, production/release/issue closure, or cloud/AWS action.
