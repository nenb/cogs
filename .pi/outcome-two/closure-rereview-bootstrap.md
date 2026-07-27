# Outcome 2 R2 hostile rereview — trusted closure bootstrap

- Review ID: `O2-R2-BOOT`
- Exact reviewed head: `d845cb13111cc3077141d84a3796537bd125dd0b`
- Governing decision: accepted ADR 0088
- Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- Inputs read in full: all five first `closure-review-*.md` reports, all four `closure-*-correction.md` designs, and ADR 0088.
- Scope: T0/pre-import source admission, held-byte synthetic loading, tracked-schema bytes, ambient preparation guard, issuer `SCM_RIGHTS`/nonce/credentials/one-shot behavior, report/descriptor/generation binding, and resulting native readiness.
- Disposition: review only. No production, schema, test, fixture, workflow, native, namespace, mount, cloud, provider, or deployment change or execution was made.

## Verdict

**BLOCKED: two P0, four P1, and one P2 findings remain. No new P3 finding.**

The exact head adds useful mechanisms: fixed source-set/blob authentication precedes parser/closure execution on the intended route; held tracked-schema bytes are applied independently; complete sealed descriptor bytes are hashed on both sides of an `SCM_RIGHTS` transfer; the packet carries a random nonce and source/report/generation digests; and the public `prepare_fixed_runtime_closure()` function is inert. Those mechanisms do not close ADR 0088 because the private preparation gate is forgeable, the real synthetic loader does not run, the portable launcher routes are label players rather than adapters over production, final mapping is not synchronized to successful exec, and T2 claims/policy remain stronger than observations and implementation.

Native readiness is **NO**. Do not begin Jobs A–E or thin integration at this head.

## Findings

### P0-1 — The ambient preparation guard is only duck typing and can be forged before the first real effect

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:1509-1519,1586-1591,1676-1684,1693-1696`; `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:63-74`.

The public function at lines 1693-1695 correctly rejects. The authority-bearing private function at lines 1676-1678 remains callable after an ambient import, however, and `_claim_admission()` accepts any caller object exposing a method named `_claim_runtime_closure_admission` that returns `True` plus three correctly shaped strings. It does not bind the object to the bootstrap-created `_SourceAdmission`, the synthetic package, the live issuer endpoint, the admitted worker PID, or a kernel capability. `_prepare_state_machine()` also deletes its `issuer` argument before admission and starts system effects immediately after the duck-typed claim.

A review probe imported the closure normally, supplied a five-line forged object with those attributes and a caller validator, and `_claim_admission()` printed `forged ambient admission accepted`. The same object can reach `_prepare_admitted_fixed_runtime_closure()`; on Linux x86-64 it proceeds to fd/proc/source authority. `__all__ = ()`, underscore names, and the separately guarded public alias do not enforce the accepted “only admitted worker” boundary.

This leaves the original pre-effect P0 open. The guard must require bootstrap/issuer authority that ambient caller data cannot synthesize, and every authority-bearing entry—including private/test aliases available in a normal import—must reject before `_Ops.architecture_gate`, fd enumeration, procfs, or source access.

### P0-2 — Production still publishes T2 facts it does not establish, and the fixed seccomp policy permits replacement

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:322-337,679-700,724-781,962-1000`.

The BPF deny list at lines 323-325 omits x86-64 `seccomp` (317) and `prctl` (157), although ADR 0088 explicitly requires seccomp replacement denial. Lines 698-700 install one filter, then turn the io_uring/namespace/mount/replacement/acquisition “checks” into no-op `_security_operation` labels because `_SystemOps` has no model `operation()` method and no effect is supplied. Capability verification reads only effective/permitted/inheritable words at lines 691-692; bounding and ambient zero are not reread.

The coordinator nevertheless constructs `RuntimeQualificationResult` with every mapping, namespace, PID-1, capability, securebits, NNP, seccomp, descriptor, child, descendant, mount, and path boolean set to literal `True` at lines 995-1000. It compares direct child bytes, descriptors, and one path, but does not independently observe all those facts. The namespace owner also uses blocking `waitpid(child, 0)` and raw-PID KILL/wait cleanup at lines 757 and 770-774, contrary to the accepted bounded exact-identity lifecycle.

This is not merely missing native proof: the production result itself overclaims and the production filter lacks a required denial. The prior real-T2 P0 and truthful-result P2 remain open.

### P1-1 — The admitted synthetic load fails after `sys.path` is emptied

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1228-1245,1271-1279`; `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:7-21`.

The bootstrap clears `sys.path` at line 1274 and only pre-creates the two tracked private modules. Executing the held closure bytes then performs standard-library imports including `platform` at closure line 14. `platform` is not imported by the launcher and is not preloaded by this loader. Two isolated static probes (the host Python and `/usr/bin/python3`) called the exact `_load_private_closure()` with the exact held source set and both failed:

```text
ModuleNotFoundError: No module named 'platform'
```

Thus the intended authenticated route cannot reach `_coordinate()`. The green bootstrap portable cases never execute this loader (P1-3). Preserve a fixed standard-library import mechanism while excluding checkout/ambient tracked modules, or preload and bind the complete allowed stdlib set before clearing search state; then directly test the exact held-byte load.

### P1-2 — “Exec blocked” is a no-op; final maps can be sampled before gzip/zstd exec

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:263-268,747-756,787-821,855-867`.

The namespace owner reports the child PID immediately after `fork()`, without a CLOEXEC status handshake proving `execveat` completed. The parent receives that PID, calls `_security_operation(ops, "exec.blocked")` with no effect, and immediately reads maps. With `_SystemOps`, that label does nothing. The sample can therefore race against `_enter_boundary()` and `_child_fd_install()` and observe the Python pre-exec image instead of the final gzip/zstd image.

Input remains closed until after the map call, which is good, but the accepted ordering is specifically successful exec → stable final mapped-generation equality → input release. A scheduling race is not an exec proof. This leaves the prior execution-generation P0 materially unresolved and makes native success nondeterministic/fail-closed rather than qualifying the required boundary.

### P1-3 — Launcher portable “adapters” are dead parallel implementations that manufacture the requested transcript

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1033-1138`; `test/outcome-two-trusted-launcher-portable.py:155-214`; `test/outcome-two-recovery-portable.py:303-320`.

`_drive_fixed_bootstrap_with_adapter_for_tests()` iterates attack-name strings. `_drive_fixed_issuer_with_adapter_for_tests()` iterates attack-name strings and then four success labels; it never calls `_WorkerIssuer`, `_consume_issuance`, `sendmsg`, `recvmsg`, credential parsing, or descriptor inspection. `_drive_fixed_t2_with_adapter_for_tests()` replays `_T2_SEQUENCE`, mutates synthetic sets, then sets every claim true. `_drive_fixed_outer_recovery_with_adapter_for_tests()` manually forks/kills/waits a harmless pipe child rather than driving `_coordinate`, `_worker_main`, namespace ownership, issuance, or production recovery.

The test at lines 155-214 only asserts those fabricated routes replay the fixture strings. This directly violates ADR 0088 P1-6 and explains why the synthetic-load, seccomp, result-overclaim, and pre-exec mapping defects are green. These helpers are test-only dead code: repository search found no production caller and only the matching portable tests. Replace them with primitive adapters used by the actual bootstrap/issuer/T2/recovery state machines; attack rows must fault those real operations.

### P1-4 — The issuer protocol is substantially improved but not exact for credentials, packet cardinality, or generation-row coverage

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:406-449,450-485,574-605`.

Positive improvements are real: `SOCK_SEQPACKET|SOCK_CLOEXEC`, `SO_PASSCRED`, a 256-bit `getrandom` nonce, `SCM_RIGHTS`, `MSG_CMSG_CLOEXEC`, expected sender PID, complete descriptor hashing/seals, report/schema/codec checks, admission/report/binding/generation digests, and a one-use `_used` flag are present.

The remaining exact-contract gaps are:

1. `_credentials()` unpacks `(pid, uid, gid)` but returns and validates only PID; UID/GID are discarded. It also combines any number of `SCM_RIGHTS` records instead of requiring exactly one rights record and exactly one credential record.
2. `_consume_issuance()` reads one record and returns after acknowledgement without proving EOF/no second packet.
3. `_verify_bundle()` requires rows to be sorted but not unique or exactly equal to every `(tool_index, object_index)` for gzip and zstd. A report object whose descriptor aliases one already referenced can lack its generation row while `referenced == descriptors` still passes.

These gaps do not restore the old public three-integer handoff—the kernel-backed transfer is a major correction—but they leave the accepted exact credential/one-packet/every-object generation binding incomplete. They also have no real protocol hostile coverage because of P1-3.

### P2-1 — The fixed-Python check compares a resolved proc target to a symlink spelling

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:1246-1254`; `.github/workflows/ci.yml:18`.

The native target is Ubuntu 24.04. `_bootstrap_main()` invokes `readlink("/proc/self/exe")` and requires the result to equal `/usr/bin/python3`. On standard Ubuntu, `/usr/bin/python3` is a symlink and `/proc/self/exe` names the resolved versioned executable (for example `/usr/bin/python3.12`). Therefore the fixed invocation `/usr/bin/python3 -I -B -` is rejected despite being the required invocation.

This is fail-closed, not an authority bypass, but it independently prevents native readiness. Authenticate the invoked executable identity without comparing a resolved kernel link to an unresolved symlink spelling, and add a Linux production-path test.

## Prior finding disposition

| First-review area | R2 disposition at `d845cb1` |
| --- | --- |
| Pre-effect T0/T1 admission | **Open (P0-1)**. Source bytes are authenticated before intended parser/closure execution, but ambient callers can forge the private admission object. |
| Held-byte synthetic loading | **Open (P1-1)**. Exact source/blob/digest work exists; the exact loader fails on an unpreloaded stdlib import. |
| Public/raw handoff forgery | **Materially improved, not closed (P1-4)**. Raw dataclass authority is gone from the intended route; real `SCM_RIGHTS`/nonce/digest binding exists, but exact credentials, packet count, and every-object rows are incomplete. |
| Report + executable descriptor binding | **Materially improved**. Complete bytes, sizes, hashes, access modes, CLOEXEC and seals are checked by issuer and consumer. Exact generation-row coverage remains open. |
| Final loader/library generations | **Open (P1-2)**. Complete objects are copied and map-file bytes are hashed, but no exec-complete handshake orders the final map check. |
| Real T2/truthful probe | **Open (P0-2)**. Namespaces/root/cap-drop/filter operations exist, but policy and result facts overclaim; lifecycle is not the accepted exact owner. |
| Outer recovery/child lifecycle | **Open (P0-2/P1-3)**. Production retains unbounded/raw-PID branches; portable recovery is a separate manual child demonstration. |
| Tracked schema + independent codec | **Resolved on the intended admitted route**. Authenticated held schema bytes are applied separately from producer and consumer semantics. P0-1 still permits an ambient forged validator on the bypass route. |
| Linux fd enumeration, close poison, helper stdio/complement | **Materially corrected in core code and direct portable suites**; no final closure sign-off because the composed production launcher/recovery adapters remain absent. |
| Page-granular ELF and core fixture truth | **Materially corrected**; direct parser/core suites pass and current line highs are within ADR 0088. |
| Historical predecessor whitespace P3 | **Disposition accepted by ADR 0088**; exact correction-range and exact-head diff checks are clean. |

## Static/portable checks

Review host: Darwin 24.6.0 arm64. No Linux-native primitive, sudo, namespace, mount, seccomp, `map_files`, compression-tool qualification, cloud, AWS, provider, or workflow run was attempted.

| Check | Result |
| --- | --- |
| `git rev-parse HEAD` | **PASS** — exact `d845cb13111cc3077141d84a3796537bd125dd0b` |
| Seven direct `/usr/bin/python3 -I -B test/outcome-two-*portable.py` suites | **PASS** |
| Same seven under `/usr/bin/python3 -O -I -B` | **PASS gate** — all rejected optimized mode with exit 1 |
| `python3 -I -B -m py_compile` on three production modules and seven Python suites | **PASS**; generated caches removed |
| Exact synthetic held-byte load probe after `sys.path=[]` | **FAIL contract** — `ModuleNotFoundError: platform` |
| Ambient forged-admission probe against `_claim_admission()` | **FAIL contract** — forged object accepted |
| `git diff --check 32ba6e0..HEAD` and `git diff --check HEAD^..HEAD` | **PASS** |
| `git fsck --no-progress --no-dangling` | **PASS** |
| `npm` TypeScript/schema/full checks | **NOT RUN / environment blocked** — locked `node_modules` is absent |
| Native Jobs A–E / thin integration | **NOT RUN and not authorized** |

Green portable output is not sign-off because the launcher suite drives the dead label routes identified in P1-3, not the production bootstrap/issuer/T2 implementation.

## ADR 0088 line-high check

Gross/current physical additions from the accounting predecessor remain within every revised high:

| Surface | Actual | High |
| --- | ---: | ---: |
| parser / closure / launcher | 306 / 1,696 / 1,296 | 320 / 1,700 / 1,300 |
| schema / schema registration addition | 134 / 27 | 260 / 30 |
| seven Python portable suites | 336 / 232 / 250 / 394 / 378 / 225 / 238 | 350 / 300 / 300 / 400 / 400 / 300 / 500 |
| TypeScript wrapper / fixture aggregate | 83 / 433 | 150 / 700 |
| **Trusted/portable subtotal** | **6,028** | **7,010** |

Numeric compliance does not cure the findings. Closure has 4 lines and launcher 4 lines of per-file headroom; readable correction will require deletion/replacement within the accepted gross highs or another ADR before crossing one.

## Native readiness decision

**NOT NATIVE READY.** The exact production admission route currently cannot load, an ambient caller can bypass the claimed private guard, the T2 filter/result and lifecycle remain inexact, and the final map check is not ordered after successful exec. Native Jobs cannot repair those production defects and must not be used to convert unavailable/failure into evidence.

Required next gate: fix P0-1 through P2-1; make portable tests drive the exact production bootstrap, socket protocol, T2, final-map, and recovery state machines; rerun all locked static/portable checks; then obtain another exact-head hostile review with no unresolved P0–P3 before native A–E.

O2-R2-BOOT COMPLETE
