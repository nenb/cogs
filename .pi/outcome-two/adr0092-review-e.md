# ADR 0092 exact-head hostile review — E

- **Exact implementation head:** `3846383f0d88c190226356ca9aeeeda402943aaa`
- **Scope:** independently pinned root capsule, root checkout exclusion, sandbox-only dispatch, post-chroot readback, inner-process preregistration/transfer/cleanup, Job E client, and portable acceptance.
- **Execution boundary:** static and portable review only. No sudo, namespace, mount, seccomp, native selector/workflow, network, provider, cloud, or AWS action was invoked.
- **Disposition:** **BLOCKED** — one P0, one P1, and two P2 findings. No P3 finding.

## Severity summary

| Severity | Count |
| --- | ---: |
| P0 | 1 |
| P1 | 1 |
| P2 | 2 |
| P3 | 0 |

## P0

### P0-1 — The “independent” root authority is still selected by the unprivileged sudo caller

`_root_capsule_authority()` derives the authority in the unprivileged launcher, `_render_root_bootstrap()` substitutes that caller-created value into Python source, and `_run_root_capsule_with_ops()` supplies the resulting source directly as sudo's `python3 -c` argument (`completion_trusted_runtime_launcher.py:2510-2531,2575-2581`). Root compares the capsule with the embedded value before compilation (`:2473-2503`), but both values remain under the same caller's control.

This would become non-forgeable only if a root-controlled policy allowed exactly one rendered command. The reviewed head contains no such policy or setup. Job E runs on a stock `ubuntu-24.04` hosted runner and directly enters the driver (`.github/workflows/ci.yml:357-383`); the API note itself defers command pinning to a later execution ADR/sudo policy (`.pi/outcome-two/adr0092-launcher-api.md:34-36`). A later ADR cannot make this exact workflow install a missing policy without changing the reviewed source/head.

Consequently a process able to use the runner's sudo authority can render a different authority, provide a matching self-consistent capsule, and reach `exec(compile(launcher, ...))` as root. The new comparison closes capsule-only substitution under a pre-pinned command, but the production workflow does not provide that independent root pin. ADR 0092 §1 and the root-capsule P0 are not closed.

## P1

### P1-1 — An inner child can escape the outer owner's all-path reap authority before transfer

The leader creates the inner child under a leader-local `_ProcessOwner` at `completion_trusted_runtime_launcher.py:2783`. The child blocks on its release pipe, but does not arm `PDEATHSIG` until **after** that pipe releases (`:2692-2698`). The outer/root owner receives the pidfd only later at `:2901-2911`.

If the outer transaction rejects or times out while waiting for the transfer, its cleanup knows only the leader (`:2935-2941`). Stopping that leader can terminate it without running the leader's Python cleanup. The blocked inner then sees release-gate EOF and exits 125, is adopted by the root subreaper, but is absent from the outer owner's process list and is never bounded-waited/reaped before subreaper restoration. The failure path performs no recursive census/reap of such an adopted unknown child.

Local preregistration is therefore lost with the leader during the exact pre-transfer failure window. This violates ADR 0092 §7's requirement that every inner process be registered and settled on all paths.

## P2

### P2-1 — Portable acceptance never executes or faults the E sandbox production state machine

`capsule_contract()` directly calls `_decode_root_capsule()` and searches source text (`test/outcome-two-trusted-launcher-portable.py:678-733`). `common_production_adapters()` substitutes completed results. The added outer corpus exercises `_run_held_python_with_ops`, not `_sandbox_only_transaction`, `_sandbox_leader`, or `_sandbox_inner`. The focused Job E test stops deliberately at a mocked common operation boundary (`test/native-qualification-e.test.ts:74-98`).

There is no declared E corpus for clone/registration/transfer/ack/release, post-chroot status/readback, child/leader exit, signal/wait/reap, mount cleanup, namespace-handle cleanup, or subreaper restoration cuts. The tests therefore cannot detect P1-1, removal/reordering of the post-chroot readback, or false all-path cleanup claims, and do not meet ADR 0092 §9's declared/selected/consumed/oracle equality requirement for E.

### P2-2 — The frozen exact-head launcher identities are stale

The API note records launcher SHA-256 `9291ca...`, Git blob `2114d4...`, and source-set SHA-256 `25aeb9...` (`.pi/outcome-two/adr0092-launcher-api.md:44-50`). At the exact reviewed head the corresponding values are:

- launcher SHA-256: `7ab2a2892aac4c561144592ec1b5ed83360222f86d2e6ccaa85f596ec7d43065`
- launcher Git blob: `500849612c939f4a038bc201f04199ee74b232ca`
- four-source framed SHA-256: `5844f093e09913bd9d4345edc49994527ee8b826c85f7d21fb68fe0868ca40b7`

Only the documented root-bootstrap template hash still matches. The note therefore cannot freeze the exact command/source authority for a later execution decision as claimed.

## P3

None.

## Confirmed properties

- Common authenticates held source/client generations before compiling the held launcher, and the nominal root bootstrap opens no checkout pathname.
- Under an externally pre-pinned rendered command, root compares revision, launcher digest, source-set digest, and ordered source rows before compiling supplied launcher bytes.
- Nominal root dispatch calls only `_sandbox_only_transaction`; it does not load the closure for sandbox mode.
- The inner reports only after `_enter_boundary()` has chrooted, and the outer performs `/proc/<pid>` mount/root readback while the inner is held behind its final gate (`completion_trusted_runtime_launcher.py:2720-2728,2912-2925`).
- The happy path transfers and registers the inner pidfd before release and retires both inner and leader.
- Job E independently fixes the production seccomp-policy digest and rejects false/open/cross-profile result shapes.
- Gross additions are at, but do not exceed, the ADR 0092 individual highs: launcher `3500/3500`, trusted-launcher portable `1200/1650`, Job E driver `188/540`, and Job E test `137/320`.

## Verification

- `git rev-parse HEAD` — exact `3846383f0d88c190226356ca9aeeeda402943aaa`.
- `git diff --check` — pass.
- Python compile/AST check for launcher and Job E — pass.
- `/usr/bin/python3 -I -B test/outcome-two-trusted-launcher-portable.py` — pass.
- `/usr/bin/python3 -I -B test/outcome-two-lifecycle-portable.py` — pass.
- `node --test --import tsx test/native-qualification-e.test.ts` — not run: local `tsx` dependency is absent; no dependency acquisition was attempted.

The passing portable suites do not exercise or override the findings above.

# Verdict: BLOCKED

Do not sign off ADR 0092 E at `3846383`. Do not authorize native execution, workflow dispatch/rerun, sudo, artifact reliance, provider/cloud/AWS activity, production, release, or issue closure.
