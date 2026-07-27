# Outcome 2 capability driver review

**Scope:** accepted ADR 0087, `OUTCOME-TWO-PLAN.md`, `.pi/outcome-two/capability-implementation-gate.md`, and the exact current `scripts/runner-capability-probe.py` at `9c86bc5`.

**Verdict:** blocked; 3 P1 and 3 P2 findings.

## P0

No findings.

## P1

### P1-1 — A supervisor crash can strand privileged or irreversible case processes

**Lines:** `scripts/runner-capability-probe.py:163-183`, `257-280`, `772-786`, `1170-1174`, `1579-1588`.

Children are started without a child-side parent-death contract or an outer recovery supervisor. The sudo process is also registered only after the parent has written and closed the helper-input pipe (`163-183`). The only recovery is in-process exception handling (`1579-1588`), which cannot run after `SIGKILL`, a fatal interpreter crash, or the job timeout. Consequently, a sudo/root helper, `unshare` process, or mount/namespace case can outlive the supervisor with no remaining deadline enforcer or exact reaper. This violates C12/C15 and the gate's requirement that crash, timeout, and partial initialization cannot leave uncertain process or mount residue; runner disposal is explicitly not cleanup proof.

### P1-2 — A complete report can claim descriptor restoration without a descriptor baseline or complete close accounting

**Lines:** `scripts/runner-capability-probe.py:116-121`, `132-139`, `347-400`, `446-450`, `1283-1297`.

`descriptors_restored` starts as `True`; the driver never captures or compares the pre-effect descriptor baseline. Several parent-owned chain descriptors are closed through `safe_close()` while its failure result is discarded (`396-400`), and the replacement descriptor close is likewise ignored (`446-450`). Finalization then copies that optimistic boolean directly into cleanup and can select `outcome="complete"` (`1288-1297`). A failed/uncertain close can therefore coexist with a complete report, contrary to C15's baseline-restoration rule and the gate's requirement to aggregate every close failure.

### P1-3 — The 120-second supervisor deadline does not bound the operation sequence

**Lines:** `scripts/runner-capability-probe.py:145-150`, `163-192`, `401-458`, `1178-1201`, `1202-1278`.

Deadline expiry merely sets uncertainty and returns a 1 ms child wait. `Ledger.run()` starts the child before consulting `remaining()` (`163-192`), fixed-tool reads do not consult the deadline at all (`401-458`), and `probe_linux()` continues launching every later case, including sudo cases, after prior work (`1202-1278`). Thus the nominal global deadline neither prevents new effects nor bounds hashing, helper input, syscall work, or cleanup. The three-minute workflow timeout can become the actual bound and hard-kill the supervisor, feeding directly into P1-1.

## P2

### P2-1 — Temporary-name and mount cleanup authority is pathname/global-state based, not identity-bound

**Lines:** `scripts/runner-capability-probe.py:25`, `54`, `556-605`, `1124-1159`.

Ownership of the fixed `/tmp` tree is represented only by `PRIVATE_PARENT_OWNED`; no retained parent descriptor or recorded object identity authenticates later mount targets, unmounts, or removals. Mounts are unmounted by string (`602-604`), and cleanup removes absolute names (`1143-1158`). This does not satisfy C15/the gate's fd-relative, identity-bound exact-name and exact-mount cleanup contract and cannot distinguish the created generation from a replaced name.

### P2-2 — The approved tool chain does not authenticate the root path component's policy

**Lines:** `scripts/runner-capability-probe.py:347-350`, `361-384`.

The resolver records `/` generation but never requires that initial component to be UID 0 and non-group/world-writable. Those checks begin only for subsequently opened components. A host with a mutable or non-root-owned root component can therefore still produce an `ok` fixed-tool identity, contrary to C8's component-by-component root-owned, non-writable chain rule.

### P2-3 — Forked case crash output can escape directly to the job log

**Lines:** `scripts/runner-capability-probe.py:257-279`, `728-750`.

`fork_case()` creates only a result pipe and does not redirect child stdout/stderr before running case code. Nested children such as the PID-namespace child inherit those descriptors as well. Although Python exceptions are converted to exit 120, a fatal runtime/native crash can write uncontrolled diagnostics directly to inherited stderr (or stdout), bypassing the bounded categorical record. This conflicts with C11 and the gate's requirement that probe-child output never reach the log and that crash paths emit no uncontrolled report/diagnostic bytes.

## P3

No findings.

## Focus-area disposition

- **Root-helper immutability / checkout isolation:** no separate finding. The larger root helper is a loaded module literal and is supplied over stdin to fixed `/usr/bin/python3 -I -`; no checkout pathname crosses sudo.
- **Privilege and fixed executable selection:** no separate finding beyond P1-1/P1-3. Sudo is noninteractive, uses fixed `/usr/bin/*` paths, and receives an empty environment.
- **Bounds:** P1-3 and P2-3 apply.
- **Resource identity and process/mount/fd cleanup:** P1-1, P1-2, and P2-1 apply.
- **Crash output:** P2-3 applies.
- **Network/acquisition:** no finding. The driver contains no network/acquisition client or package/tool acquisition route; executable case helpers install the fixed socket/io_uring deny filter before case work, subject to the accepted loader/runtime pre-filter limitation.

## Checks performed

- `/usr/bin/python3 -I -B scripts/runner-capability-probe.py --self-test` — passed.
- Workflow portable tests — passed.
- Driver TypeScript suite could not start in this worktree because `ajv/dist/2020.js` is not installed; this review does not classify that local dependency state as a production finding.

CAP-REVIEW-DRIVER COMPLETE
