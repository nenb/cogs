# ADR 0091 final E/integration signoff review

- **Exact implementation head reviewed:** `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08`
- **Scope:** held-byte/root capsule, production sandbox-only E owner, thin integration, common admission/report ownership, exact E/integration results, focused and trusted portable tests, schema/workflow composition, and all-path cleanup.
- **Method:** fresh hostile static and portable review. No `--workflow-bound` selector, sudo, namespace, mount, seccomp, `map_files`, `close_range`, compression executable, native workflow, network acquisition, provider, cloud, or AWS operation was invoked.
- **Disposition:** **BLOCKED** — one P0, three P1, and one P2 finding remain. No P3 finding.

## P0

### P0-1 — The root capsule is self-signed and lets the fixed sudo bootstrap execute attacker-selected Python as root

The root bootstrap has no independently trusted launcher digest, source-set digest, revision, issuer capability, or nonce. It accepts `parent_pid` from the same capsule writer, requires only that it equal the writer's actual parent PID, recomputes digests over caller-supplied rows and payload, compares the launcher digest to the caller-supplied `bootstrap_sha256`, and then compiles/executes those caller-supplied launcher bytes (`completion_trusted_runtime_launcher.py:2125-2128,2173-2197`). `_encode_root_capsule()` likewise puts values derived from its own supplied source mapping into the header (`:2198-2202`).

Consequently any unprivileged process able to invoke the documented exact sudo command can copy `_ROOT_BOOTSTRAP`, choose arbitrary bytes for the launcher row, set `bootstrap_sha256` and `source_set_sha256` consistently, set `parent_pid` to itself, and have those bytes executed by root at `:2195-2196`. The malicious launcher need only define `_root_capsule_entry`; its top-level code has already run by then. The parent-PID equality proves direct transport, not issuance by the admitted holder.

This defeats root-capsule authenticity before the first root effect. It also makes the E sandbox-only boundary forgeable: nominal code does not load the closure for sandbox mode, but a forged launcher can perform closure/compression or arbitrary root work. The fact that the nominal command passes only fds 0–2 and opens no checkout pathname does not repair arbitrary held-byte root execution.

## P1

### P1-1 — Common executes checkout-derived launcher bytes before authenticating them to the exact Git head

`SystemCommonOps._launcher()` opens and generation-binds the launcher, computes an unreferenced SHA-256, and immediately executes it in the native driver process (`common.py:197-208`). Only methods supplied by that newly executed module later enter `_prepare_held_client()` and authenticate source rows against Git (`common.py:232-249`; launcher `:2015-2043`).

Thus a replacement launcher generation can execute arbitrary top-level code before any exact-head/source-set admission and can itself invoke the sudo route. Holding bytes closes pathname reread but does not authenticate those bytes. This is the same ambient/self-authenticating authority shape ADR 0091 forbids.

### P1-2 — The E sandbox owner contains an unregistered raw-fork descendant with no all-path recovery

Inside `_sandbox_only_transaction`, the registered leader directly calls `os.fork()` for the PID-namespace inner process (`completion_trusted_runtime_launcher.py:2358`). The inner child is not blocked, pidfd-owned, transferred, or registered with `_ProcessOwner`; it begins fd, mount, boundary, and result effects immediately (`:2359-2373`). The leader manually polls `waitpid` only on the happy route (`:2374-2383`). Any exception after the fork makes the leader call `os._exit(125)` (`:2385-2386`) without terminating/reaping that inner process. The outer owner tracks only the leader and later derives descendant/namespace release from an empty leader registry (`:2399-2402,2427`).

This violates exact child preregistration, descendant authority, and all-path cleanup. E cannot truthfully emit `descendants_reaped`, `namespaces_released`, or `namespace_handles_released` from those predicates.

### P1-3 — The report custodian leaves owned report state and processes on ordinary failure cuts

The custodian creates the report directory at `common.py:554`. Its exception path only identity-checks/unlinks matching staged, published, and receipt files (`:622-636`); it never removes the now-empty owned directory, fsyncs `/tmp`, closes/reaps through a bounded owner, or proves baseline restoration. A failure immediately after `mkdir` (for example parent `fsync` at `:555`) has `directory is None` and necessarily leaves `/tmp/cogs-native-qualification-{job}`. Later write/fsync/rename/readback cuts can leave the empty directory for the same reason.

Custodian startup is also not all-path owned: after `fork`, failures in `pidfd_open`, child-end close, START send/receive, or READY validation (`:507-528`) have no TERM/KILL/reap recovery for the blocked child. These are mandatory report and outer process cuts, not merely diagnostics. Upload cleanup cannot recover a publication transaction that failed before a valid receipt/report was published.

## P2

### P2-1 — Portable acceptance substitutes completed claims and cannot detect the P0/P1 branches

The capsule test constructs a self-consistent capsule from caller-supplied sources and checks only duplicate/truncated/trailing mutations and source tokens (`test/outcome-two-trusted-launcher-portable.py:653-684`). It has no negative case proving that a self-consistent unauthorized launcher is rejected by an independent root authority. `common_production_adapters()` replaces both `_git_tree` and `_run_held_python_with_ops`, then returns preassembled all-true result dataclasses (`:705-838`). Job E's focused “root capsule” test is a fake `Session` that appends `runner-admitted`/`root-consumed` events itself and never reaches production (`test/native-qualification-e.test.ts:74-103`).

The common focused test exercises `_write_all`, `_read_all`, and `_name_matches` in isolation but never drives `_start_custodian`/`_custodian_main` failure recovery. The trusted recovery fixture does not cover the E inner raw fork or common custodian. Therefore branch-removal and all-cut requirements in `AT91-BOOT-01`, `AT91-OUTER-01`, `AT91-REPORT-01`, and `AT91-E-01` are not met even though the present portable launcher suites pass.

## P3

None.

## Confirmed properties

- On the nominal exact implementation path, root executes `/usr/bin/sudo -> /usr/bin/env -i -> /usr/bin/python3 -I -B -c`, receives only fds 0–2, and does not open or execute a checkout pathname or descriptor.
- Nominal sandbox dispatch sets `closure_module = None`; `_root_capsule_entry` calls `_sandbox_only_transaction`, not the ordinary closure/compression coordinator.
- `job-e-sandbox.py` and `thin-integration.py` themselves are narrow session clients and contain no parallel sudo/pipe/fork/unshare/mount/process supervisor.
- Thin integration requires the exact ordered ordinary result inventory, exact version/marker/source binding, all booleans true, and both fixed output digests. Cross-profile, missing, extra, reordered, false, and wrongly typed values reject.
- Common converts only exact production dataclass types before exposing primitive dictionaries to drivers; operation binding is one-shot and job-exact.
- Gross additions remain within the ADR 0091 listed file highs and binding subtotals. Exact correction-commit `diff --check`, Python AST parsing, and repository integrity checks passed.

## Portable/static verification

- `/usr/bin/python3 -I -B test/outcome-two-trusted-launcher-portable.py` — **pass**.
- `/usr/bin/python3 -I -B test/outcome-two-recovery-portable.py` — **pass**.
- Focused TypeScript tests were not run because this clean review workspace has no `node_modules`; no network/dependency acquisition was attempted.

The passing portable suites do not exercise or override the findings above.

# BLOCKED

Do not sign off ADR 0091 E/integration at `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08`. Do not authorize a native selector, sudo/native run, workflow dispatch, artifact reliance, cloud/AWS action, production use, release, or issue closure. Resolve every P0–P2 finding and restart all five exact-head reviews.
