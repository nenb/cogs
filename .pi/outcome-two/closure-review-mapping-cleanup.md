# Outcome 2 Wave 2 — exact-head mapping and cleanup hostile review

**Reviewed head:** `64c055762e260b8fc2eed96741bdb30c89183f3c`

**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`

**Authorities read:** accepted ADR 0087, `OUTCOME-TWO-PLAN.md`, `.pi/outcome-two/closure-audit.md`, and `.pi/outcome-two/portable-audit.md`.

**Exact surfaces read:** the three new production modules, trusted-closure schema and schema registration, all seven Outcome 2 Python portable suites, the TypeScript wrapper, and every `test/fixtures/outcome-two/**` fixture.

**Disposition:** review only. No production file was changed. No native qualification, workflow, sudo, namespace, mount, provider, cloud, AWS, or deployment action was run.

## Verdict

**BLOCK — no P0, three P1, three P2, and one P3 finding remain.**

The source-descriptor-direct gzip/zstd sealing path, exact seal masks, bounded maps-to-EOF capture, maps-before/maps-after byte equality, and resolved/mapped set equality are materially improved over the audited candidate. They do not cure the owner baseline defect that prevents a real Linux owner from becoming `READY`, the unbounded/inexact child cleanup paths, or the portable-suite blind spots that allowed those defects through.

Do not hand off this closure, begin native Jobs A–E, or run thin integration at this head.

## Exact implementation binding

| Surface | Git blob | SHA-256 |
| --- | --- | --- |
| `deploy/aws-feasibility/remote/completion_elf.py` | `5e3ba497a5862eb039b4b3a984e877c3dc470c9f` | `21f794d9175b4daa6526cba0df477ad31ea9b5d870576c1ffbc1761e7d1e7c5e` |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py` | `508378c42810729b43c300aea58d3ae3f1eda292` | `b0c4b1c8f466582e3638020ee6451ce68cb01e16f4e7d2ac1bde84fac0d61436` |
| `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py` | `0b00f02e0f45b5fc4850c85df56dfd4c819e2d1d` | `72a72b46bbf5b3b9948fe6c145d002080f49d726d7fc87478294a103cff7d556` |
| `schemas/trusted-runtime-closure-v1.json` | `cdd8abf68df367b4839511d34e0ffd8c0de1201a` | `8a57f0fe87191dc8bc295d06112f25478b4739eea96262f64bc6e20e33905610` |
| `test/outcome-two-runtime-closure-portable.py` | `debba331e3f5c60f7fdafbd7f8d7c372699584ee` | `efba3584234814cc6a548fee35ae97747c3ef84e3276f75bb71a73d58d0c2bd7` |
| `test/outcome-two-mapped-closure-portable.py` | `73581e0be05eca93726d61567e34425b30677284` | `f16aa291f3736141b08478fe47ab87d9d69d23b32369acb0eb1382f6e5f77676` |
| `test/outcome-two-sealing-portable.py` | `6f984a145b1a34167b842f6de2982b60611890eb` | `0ec388bf8b61a0cca9652061859023905fc35f7e1985a9b3ea0954f3503e72ba` |
| `test/outcome-two-lifecycle-portable.py` | `f8f5cef518c8b0518a0c659f095ac1473bf67321` | `ad1c1988700db9730c5e6112ff88913aca3c96d90c887a1f7a61c80fe10076c0` |
| `test/outcome-two-recovery-portable.py` | `590a6635ef6ed72ddb01e60c333f46ce6a72bdad` | `9a2427186faa076d0c39bf37312e6ae97671e0b327b998e361dd47bd8fb80975` |
| `test/outcome-two-runtime-report-portable.py` | `ed26aef735a61ed7abfcce9ae42934d880ef3243` | `6425bc21e33c13ee723f4751ced64860468afeccc3862e046972024d9bb33a8a` |
| `test/outcome-two-trusted-launcher-portable.py` | `9d2b58ef4a047a90d25ebf402b636aacb465c944` | `240d141f5044e9bc932f0b7b542745fafdf21638924c094478718efa0c7a78ad` |
| `test/outcome-two-portable.test.ts` | `6c341ebc57736241e848cbfea0e779b7a4fc792d` | `96f954132995672d6587d02f1eaeed904980cbc6096e90e4e7b0df61465f0c11` |

## P0

No findings.

## P1

### P1-1 — The real Linux descriptor baseline contains the enumeration descriptor, so preparation cannot reach `READY`

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:241-245,1105-1110,1116-1119,1179-1184`; `test/outcome-two-recovery-portable.py:32-56`.

`_Ops.list_fds()` calls `os.listdir("/proc/self/fd")` by pathname and includes the descriptor that `listdir` itself opens. That descriptor has closed by the time the set is returned, but it remains in `_fd_baseline`. At readiness the three output descriptors occupy new low numbers and the next `listdir` uses another number. `_prove_ready_baseline()` therefore compares a set containing the new enumeration descriptor against `baseline | outputs`, which contains the old transient number instead.

A no-network Linux container reproduction produced:

```text
baseline [0,1,2,3,4,5,6]
outputs  [6,7,8]
ready    [0,1,2,3,4,5,6,7,8,9]
expected [0,1,2,3,4,5,6,7,8]
```

Thus `_prepare()` reaches line 1182, rejects every otherwise-successful production preparation, closes the outputs, and raises a poisoned cleanup error instead of issuing a handoff. The recovery adapter replaces the real implementation with `frozenset({0,1,2} | self.live)`, so all green owner/recovery tests hide the defect.

Use an explicitly opened `/proc/self/fd` directory descriptor and exclude that exact descriptor, as the launcher already does at `completion_trusted_runtime_launcher.py:241-247`, then challenge the production `_Ops` behavior on Linux.

### P1-2 — Helper failure cleanup can signal an unvalidated identity, discard its pidfd, and return with an unreaped child

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:601-669,697-733,1140-1158,1187-1203`; `test/outcome-two-lifecycle-portable.py:216-234`.

The owner does not register the child until `_spawn_helper()` has forked, execed, completed the status handshake, opened a pidfd, and read proc identity. Any startup failure instead uses raw `kill(pid, SIGKILL)` followed by unbounded `waitpid(pid, 0)` at lines 661-665.

The settled cleanup path initially checks start time/session/process group/executable, but its emergency branch sends `SIGKILL` through the pidfd without repeating `_matching_child()`. More importantly, after TERM/KILL/reap failure it closes the pidfd unconditionally and raises. `_prepare()` merely records that `_children` is nonempty; it performs no second independently safe revalidation/reap attempt. The fixed owner can therefore return an error while leaving a helper alive and while having discarded the retained signaling identity.

This violates register-before-effect, “KILL only still-matching identities,” bounded TERM/KILL/reap, and no-child-residue requirements. The lifecycle suite checks only that the fake descriptor dictionary is empty after `wait`/`kill`/`reap` faults; it does not require `child.reaped`, model a live process independently of the pidfd, or drive this failure through `_prepare()`.

### P1-3 — The handoff launcher has neither the required child identity nor a deadline on wait/reap

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py:396-402,433-484`; `test/outcome-two-trusted-launcher-portable.py:24-66,91-111`.

`_run_fixed_tool()` retains only a numeric PID. It records no pidfd, start time, session, process group, expected executable identity, or descendant state. After both pipes close it calls blocking `waitpid(pid, 0)` outside effective deadline enforcement. On failure it signals the raw PID and performs another blocking `waitpid(pid, 0)`, again without identity validation or a fixed TERM/KILL/reap deadline.

A child that closes stdout/status and remains alive can therefore hold the launcher indefinitely after the ten-second I/O deadline. A cleanup path can also signal without the exact identity required after handoff. The scripted launcher suite replaces `run_tool` with preassembled `_ToolOutcome` values and has no test of `_run_fixed_tool`, PID reuse, identity drift, deadline-after-EOF, TERM/KILL escalation, or reap failure.

## P2

### P2-1 — Proc/map close failures do not preserve and aggregate the primary failure

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:581-586,765-789`.

Both `_read_proc()` and each `map_files` read use a bare `finally: close(fd)`. If maps parsing/authentication/readback fails and close also fails, Python replaces the active primary exception with the close exception rather than raising `RuntimeClosureCleanupError(primary, close)`. This contradicts ADR 0087’s preserve-primary/aggregate-all-cleanup-errors rule. It fails closed, but loses the exact causal and cleanup state the owner is required to retain. The map adapter never injects a close failure, let alone a primary-plus-close failure.

### P2-2 — Report preparation repeats one codec rather than independently validating the tracked schema and re-encoding twice

**Lines:** `deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py:991-1008,1169-1174`; `test/outcome-two-runtime-report-portable.py:107-124`.

Preparation calls `_validate_report_bytes()` twice on the same byte string. Both calls use the same JSON decoder, the same semantic validator, and the same encoder comparison; no tracked-schema validator runs and no second independently built encoding is compared. `schema_contract()` only inspects selected schema properties and does not validate production candidate bytes with that schema. This does not satisfy the accepted “tracked schema and independent semantic codec, re-encoded byte-identically twice” contract.

### P2-3 — Declared hostile fixtures and crash/lifecycle assertions overstate portable coverage

**Lines:** `test/fixtures/outcome-two/closure/cases.json:29-30`; `test/outcome-two-runtime-closure-portable.py:160-189`; `test/fixtures/outcome-two/maps/cases.json:9-19`; `test/outcome-two-mapped-closure-portable.py:142-167`; `test/outcome-two-lifecycle-portable.py:226-234`; `test/outcome-two-recovery-portable.py:25-46,79-135,184-192,227-235`.

The closure suite slices `hostile[:10]`, so the fixture’s object-bound and aggregate-byte cases are not fixture-driven; its separate bounds helper proves a per-tool overage, not the deduplicated three-tool aggregate bound. The maps suite never iterates `CASES["hostile"]`; in particular the declared ambiguous-fingerprint and 129-unique-object cases are not run. Lifecycle failure assertions equate an empty fake fd dictionary with cleanup and do not prove the fake child reaped. Crash cases use fake children and synthetic baselines, terminate the only subprocess with `os._exit(73)`, then call an unrelated fresh success; they do not model outer-supervisor identity/reap recovery.

These gaps directly explain why the production baseline, emergency helper, and launcher process defects remain green.

## P3

### P3-1 — The full accepted accounting-predecessor diff check is red in retained review records

**Lines:** `.pi/outcome-two/capability-rereview-driver.md:3-5`; `.pi/outcome-two/capability-rereview-schema.md:3-6`.

`git diff --check bec0a19b0b984f88ab9c2effc5059f3737915caa..64c0557` reports trailing whitespace on these seven retained lines. The narrower closure range `1cdef21..64c0557` and exact head commit are clean, so this is not introduced by the closure implementation. It nevertheless prevents a green exact accounting-predecessor check at the reviewed head and must be resolved or explicitly dispositioned without rewriting accepted review meaning.

## Prior contract and audit coverage

| Prior contract/audit item | Exact-head disposition |
| --- | --- |
| Fresh minimal helper per exact executable; Python not the preparation process | **Implemented** by `_spawn_helper()` and fixed argv/environment, subject to P1-2 lifecycle failure. |
| Complete maps to EOF under 4 MiB/4,096 lines | **Implemented and portably challenged.** `_read_stream_bounded()` performs the extra EOF read; byte and line overages reject. |
| Maps-before/maps-after byte equality | **Implemented and challenged.** |
| Open every executable nonzero-inode mapping through `map_files` | **Implemented.** Unknown, unopenable, generation-drift, missing-loader, and missing-dependency cases reject. Primary-plus-close behavior remains P2-1. |
| Exact resolved/mapped closure equality and mapping digest | **Implemented** as authenticated identity-set equality plus canonical `[role, sha256]` digest. Two declared hostile fixture cases remain unexecuted under P2-3. |
| Held-source-direct gzip/zstd sealing; no pathname reopen | **Resolved.** `_seal_source()` uses only `source.held_fd`; the sealing adapter makes every `open()` fatal. |
| Exact executable seal profile | **Resolved in production and tests:** `WRITE|GROW|SHRINK|FUTURE_WRITE|EXEC|SEAL`, exact `F_GET_SEALS`, mode `0555`, fsync, full readback, digest, and before/after source generation. |
| Owner states, one-shot handoff, CLOEXEC outputs, poison repeat | **Mostly implemented and challenged.** Real readiness is broken by P1-1; helper failure recovery is incomplete under P1-2. |
| Register before effect; exact PID identity/deadlines/reap | **Not resolved:** P1-2 and P1-3. |
| Close every fd, aggregate errors, prove baseline | **Not resolved:** P1-1 and P2-1. Generic registry close aggregation is covered, but proc/map and launcher lifecycle are not. |
| Independent schema/semantic/canonical report validation | **Partial:** schema is closed and registered; production independence remains P2-2. |
| Descriptor exhaustion, partial initialization, handoff cuts, fd reuse, double close | **Partial:** many authentication/helper/owner cuts pass, but real process and production `_Ops` behavior are replaced by adapters; P2-3. |
| Crash/recovery from fresh supervisor | **Not proved:** the suite demonstrates fresh module/process state only, not supervisor-owned child recovery; P2-3. |

## Line highs

Gross physical additions are measured from `bec0a19b0b984f88ab9c2effc5059f3737915caa`. New files were absent there, so their gross additions equal physical lines. The fixture aggregate uses the repository’s `wc -l`/LF counting convention, including binary fixtures.

| Exact surface | Actual | ADR 0087 high | Headroom | Result |
| --- | ---: | ---: | ---: | --- |
| `completion_elf.py` | 240 | 240 | 0 | at high |
| `completion_trusted_runtime_closure.py` | 1,220 | 1,220 | 0 | at high |
| `completion_trusted_runtime_launcher.py` | 599 | 600 | 1 | within |
| `trusted-runtime-closure-v1.json` | 122 | 230 | 108 | within |
| `validate-schemas.ts` Outcome 2 addition | 19 | 30 | 11 | within |
| `outcome-two-runtime-closure-portable.py` | 195 | 250 | 55 | within |
| `outcome-two-mapped-closure-portable.py` | 169 | 240 | 71 | within |
| `outcome-two-sealing-portable.py` | 156 | 210 | 54 | within |
| `outcome-two-lifecycle-portable.py` | 266 | 290 | 24 | within |
| `outcome-two-recovery-portable.py` | 249 | 290 | 41 | within |
| `outcome-two-runtime-report-portable.py` | 149 | 230 | 81 | within |
| `outcome-two-trusted-launcher-portable.py` | 149 | 280 | 131 | within |
| `outcome-two-portable.test.ts` | 48 | 120 | 72 | within |
| `test/fixtures/outcome-two/**` | 231 | 500 | 269 | within |
| **Trusted/portable subtotal** | **3,812** | **4,730** | **918** | **within** |

No current row crosses its high, but the parser and closure owner have zero line headroom. The accepted highs are gross and non-transferable; fixes cannot borrow the subtotal’s unused allowance for either file.

## Checks performed

- Exact `HEAD` and clean tracked worktree before report: **PASS**, `64c055762e260b8fc2eed96741bdb30c89183f3c`.
- Seven direct `/usr/bin/python3 -I -B` portable suites: **PASS**.
- `python3 -m py_compile` for the three production modules and seven Python suites: **PASS**; generated ignored caches were removed.
- `git diff --check 64c0557^..64c0557`: **PASS**.
- `git diff --check 1cdef21..64c0557` (closure implementation range): **PASS**.
- `git diff --check bec0a19..64c0557`: **FAIL**, retained trailing whitespace listed in P3-1.
- `git fsck --no-progress --no-dangling`: **PASS**.
- Generic no-network Linux `/proc/self/fd` baseline challenge in the already-local `python:3.10-slim` image: **FAIL contract**, reproduces P1-1 without invoking production closure or host discovery.
- `npm run schemas`: **NOT RUN / BLOCKED**, locked dependencies are absent and `tsx` is unavailable (`sh: tsx: command not found`).
- TypeScript wrapper/full `npm test`, format, and typecheck: **NOT RUN / BLOCKED** for the same missing locked dependencies. Their seven underlying Python suites were run directly.

Green portable checks do not make this head handoff-safe because they replace the exact Linux fd baseline, child process, and launcher process implementations at the failing boundaries.

## Stop decision

**STOP.** Correct P1-1 through P3-1 without crossing the two zero-headroom files, rerun the exact production-path lifecycle and Linux baseline challenges, rerun all locked repository checks, and obtain a new exact-head hostile review before native work or handoff.

O2-R-MAP COMPLETE
