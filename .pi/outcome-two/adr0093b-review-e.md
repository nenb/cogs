# ADR 0093b final exact-head hostile review — E

- **Exact reviewed head:** `0d934c9e03aae17a5f219f302cf5c09058d45c59`
- **Branch:** `review/o2-93b-e`
- **Scope:** E root source provenance, inner transfer/ownership, root and process cleanup, Job E/common receipt provenance, and the E portable corpus.
- **Execution boundary:** static and portable only. No native selector, sudo, namespace, mount, seccomp, workflow dispatch/rerun, network, provider, cloud, AWS, OpenTofu, deployment, production, or release action was invoked.
- **Verdict:** **BLOCKED — no ADR 0093 E signoff**

## Severity summary

| Severity | Count |
| --- | ---: |
| P0 | 0 |
| P1 | 1 |
| P2 | 2 |
| P3 | 0 |

## P0

None.

## P1

### P1-1 — The E acceptance gate replaces the production root issuer/bootstrap with a fabricated completed result

ADR 0093 §§8 and 10 require the complete E production state machine above mocked native primitives and explicitly make completed-result fabrication and token-only tests non-accepting. The current `full_sandbox_launch_contract()` patches `_run_root_capsule_with_ops` itself and returns a prebuilt successful `SandboxQualificationResult` (`test/outcome-two-trusted-launcher-portable.py:1388-1410`). Therefore it does not execute the production sudo process owner, its preregistration/gates/pipes/deadline/reap/cleanup, or the fixed root bootstrap in `_ROOT_BOOTSTRAP` (`deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:2516-2623,2674-2763`).

`capsule_contract()` does not close that gap. It derives the test authority from the same currently loaded launcher sources and `_ROOT_BOOTSTRAP` (`test/outcome-two-trusted-launcher-portable.py:686-713`), directly calls `_root_capsule_entry()` for hostile capsules (`:721-756`), and checks the actual bootstrap program only with substring/index tests (`:711-719,766-783`). The root-owned file opens, generation checks, fixed bootstrap digest, environment/fd envelope, parent binding, authority parsing, and pre-compilation ordering are consequently not reached as production code above a model.

This is especially material to this review: the suite can remain green if the real fixed root bootstrap or `_run_root_capsule_with_ops` cleanup regresses while the direct decoder and searched tokens remain. Static inspection found the intended independent pin, but ADR 0093 forbids using static token presence plus a fabricated completed boundary as the portable acceptance oracle.

## P2

### P2-1 — The 24-row sandbox corpus is still far short of the mandated every-cut E corpus

The fixture added only the previously missing root-open and leader-death rows. Its 24 cases (`test/fixtures/outcome-two/launcher/sandbox-process-cases.jsonl:2-25`) still omit, among other distinct production cuts:

- the second/transfer socketpair, nonce, leader gate, setsid/PDEATHSIG and parent checks;
- result/final pipe creation and adoption, inner gate/final gate, result write/read/framing, and inner exit/reap status;
- transfer send, readiness, credentials, rights cardinality, packet/binding/pidfd/identity, EOF, stable identity census, rejection acknowledgement, and post-ack failure;
- root post-create stat/fstat, root cleanup close/rmdir, descriptor-specific close failures, and cleanup aggregation;
- subreaper set, adoption pidfd/open/identity/census/TERM/KILL/reap cuts;
- drop-bounding, capset, securebits/no-new-privileges readbacks, each namespace handle and parent/user ioctl, root-link/no-proc readbacks, and several mount/restoration cuts.

The fixture mechanism cannot distinguish repeated calls to one point: `fault()` selects only a point string and first occurrence (`test/outcome-two-trusted-launcher-portable.py:914-923`), so the `outer.socketpair` row covers only the first socketpair, for example. Declared/selected/consumed/oracle equality at `:1430-1490` proves all declared rows ran, not that the required production cut set was declared. This remains contrary to ADR 0093 §§8 and 10.

### P2-2 — The sandbox model falsely treats closing a pidfd as reaping the process

`SandboxKernel.close()` sets `process.reaped = True` whenever an exited process's pidfd is closed (`test/outcome-two-trusted-launcher-portable.py:971-982`). Linux pidfd close does not reap a child; an exact parent/subreaper `wait*` is required. Because modeled children inherit descriptor records and `_task()` closes all of them (`:1119-1143`), an arbitrary child-side descriptor cleanup can satisfy this fake reap transition. `baseline_exact()` then accepts the row solely from the `reaped` flag (`:1380-1386`).

That weakens the exact correction under review: pre-transfer leader death, transferred-inner settlement, and cleanup failures can appear fully reaped even when no production wait/reap path was demonstrated. The new leader-death row is therefore not a trustworthy all-path reap oracle.

## P3

None.

## Confirmed static properties

- Root source authority is independent of capsule-selected bytes on the intended production path: the fixed sudo command names the fixed root bootstrap; the bootstrap reads root-owned fixed bootstrap/authority files, generation-checks them, and compares the exact revision, launcher, source-set, and source rows before compiling the launcher.
- Root dispatch remains sandbox-only; `_root_capsule_entry()` invokes `_sandbox_only_transaction()` and does not load the runtime closure or reopen checkout source paths.
- Nominal inner ordering is correct statically: the inner blocks on its gate; the outer receives and validates exact pidfd/credentials/identity/EOF, records the descendant and stable identity census, then acknowledges; only the leader can subsequently release the inner.
- The prior pre-transfer leader-death gap now has a static surviving-owner path: `_settle_rejected_transfer()` reaps the leader, performs stable subreaper census, adopts unregistered children by pidfd/identity, and settles them before subreaper restoration.
- `_RootOwner.prepare()` now records the created root generation before the fallible O_PATH open, and cleanup can remove that exact post-mkdir object. The selected root-open case passes with path restoration.
- Job E remains unprivileged and receipt-only. Common authenticates held source/client bytes against the exact workflow head, launches the fixed bootstrap CLI, retains one immutable operation receipt, and derives E checks/metadata from that receipt.
- Relevant gross additions remain within ADR 0093 highs: launcher `3757/4700`, common `1778/1900`, Job E `95/620`, trusted-launcher portable `2300/2300`, and fixture aggregate `527/1700`.

## Exact-head identities

- launcher SHA-256: `058093d35f1d5f1f3c5dc55becd534202746751b1fa78cd467c38767ab7668bd`
- launcher Git blob: `8699f0b2f2bb457062c732e16847bb23aa10e62b`
- four-source framed SHA-256: `b397d91ea2b8d8f48625b720ce78df3a9dbc9ef32864136bbd9dfceb3226905d`

These identify reviewed bytes only and grant no root provisioning or execution authority.

## Verification

- Seven `/usr/bin/python3 -I -B` Outcome Two portable suites — **PASS**.
- `/usr/bin/python3 -O -I -B test/outcome-two-trusted-launcher-portable.py` — **PASS as rejection** (optimized execution refused).
- Python AST parse for launcher, common, Job E, and trusted-launcher portable — **PASS**.
- `git diff --check 3846383..0d934c9` — **PASS**.
- `git fsck --no-progress --no-dangling` — **PASS**.
- Focused TypeScript Job E test — **not run** because local `tsx` is absent; no dependency acquisition was attempted.

The green portable runs do not override the replaced root production boundary, omitted cuts, or false reap semantics.

# SIGNOFF: BLOCKED

Do not authorize native execution, sudo/bootstrap provisioning, workflow dispatch/rerun, artifact reliance, production, release, issue closure, provider/cloud/AWS/OpenTofu/deployment activity, or an ADR 0093 E completion claim at `0d934c9`.
