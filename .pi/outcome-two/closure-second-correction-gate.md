# Outcome 2 second-correction acceptance gate

- Gate ID: `O2-FIX2-AUDIT`
- Audited head: `4d329b677be9b409767532f235c18ab1270be61f`
- Second-review implementation head: `d845cb13111cc3077141d84a3796537bd125dd0b`
- Authority: accepted ADR 0088, with non-conflicting ADR 0087 rules
- Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- Inputs read in full: all five `.pi/outcome-two/closure-rereview-*.md` reports, all five first `closure-review-*.md` reports, all four `closure-*-correction.md` designs, `.pi/outcome-two/closure-audit.md`, ADR 0087, and ADR 0088.
- Scope restriction: audit and acceptance-test specification only. No production, schema, test, fixture, workflow, native, privileged, provider, cloud, AWS, or deployment operation or edit was made.

## Decision

**BLOCKED. The second-review findings cannot be fixed in this task without violating the explicit “do not edit production” instruction. They also cannot all be implemented readably under ADR 0088's remaining four-line closure and four-line launcher margins.**

This is a correction gate, not a claim that the findings are fixed. Adding green tests around the existing label players would repeat the defect identified by every rereview. Adding tests which necessarily fail against unchanged production would leave the repository gate intentionally red. Therefore the exact acceptance tests below are mandatory specifications for a later production correction; none may be marked satisfied by the current suites.

Native Jobs A–E and thin integration remain blocked. Portable evidence may prove state-machine behavior and truthful handling of modeled observations. It cannot prove that a real Linux kernel supplied a T2 fact.

## Acceptance-test rules

Each ID below is a required case or case family in the named existing suite. The later implementation must add the IDs to a closed fixture ledger, execute each exactly once through the stated production method, reject unknown or unconsumed operations, and assert the intended typed error rather than “any exception.” `_SystemOps` and the model adapter must implement the same primitive protocol. Tests may fault primitives; they may not replace the production state machine with a completed result.

All success and fault runs must also assert independently modeled descriptor, process/descendant, mount, namespace-handle, named-path, limit, and checkout baselines as applicable. An unobserved fact is not `true`. Close uncertainty is permanent. Process identity authority is retained until exact reap or explicit transfer to the surviving outer owner.

### Exact acceptance-test catalog

| ID | Existing test surface and production entry | Exact case/oracle |
| --- | --- | --- |
| `AT-ADM-01` | `test/outcome-two-trusted-launcher-portable.py`; `_bootstrap_main` -> authenticated loader -> closure constructor | `ambient-public`, every ambient private/test alias, a duck-typed claim, copied claim fields, wrong synthetic package, wrong issuer endpoint, wrong worker PID, and replay all reject before architecture, fd, proc, source, helper, or sandbox operations. Success uses a live one-shot kernel-backed bootstrap/issuer capability, not a Python-name secret. |
| `AT-ADM-02` | same; `_load_private_closure` | `held-load-exact`: execute the exact admitted launcher/parser/closure/schema set with checkout search disabled while retaining a fixed standard-library loader. Include `platform` and every transitive stdlib import. Any tracked/checkout import is rejected. |
| `AT-ADM-03` | same; `_bootstrap_main` | `fixed-python-identity`: compare the kernel executable object with the descriptor-relatively admitted `/usr/bin/python3` object. A versioned symlink target is accepted only by object identity; a same-spelling replacement and alternate Python object reject. |
| `AT-ISSUE-01` | `test/outcome-two-sealing-portable.py` and `test/outcome-two-trusted-launcher-portable.py`; `_seal_object`, `_WorkerIssuer._verify_bundle` | Every issued object is transferred through a distinct `O_RDONLY|O_CLOEXEC` reference after sealing; the writable memfd reference is closed once. Wrong access mode rejects before `sendmsg`. |
| `AT-ISSUE-02` | trusted-launcher portable; `_credentials`, `_consume_issuance` | Require exactly one `SCM_CREDENTIALS` and one `SCM_RIGHTS` record, exact expected PID/UID/GID, exact fd count, no unknown ancillary data, no truncation, exactly one packet, acknowledgement, then EOF/no second packet. Duplicate/split credential or rights records reject. |
| `AT-ISSUE-03` | trusted-launcher portable; `_verify_bundle` | Binding rows are unique and equal exactly to every gzip/zstd `(tool_index, object_index)` row. Declared aliases must match one identical object; missing, duplicate, extra, conflicting, or unreferenced rows/descriptors reject. |
| `AT-REPORT-01` | `test/outcome-two-runtime-report-portable.py` plus `test/outcome-two-portable.test.ts`; production report construction, tracked-schema gate, launcher decoder | Golden and every recomputed mutant run through three distinct implementations: tracked-schema validation, producer semantic codec/re-encoder, and launcher semantic codec/re-encoder. Calling one decoder twice fails the test's implementation-identity sentinel. The exact production schema gate is entered, not just a helper codec. |
| `AT-USER-01` | trusted-launcher portable; `_namespace_owner`, `_enter_boundary` | Capture UID/GID before `CLONE_NEWUSER`; clear groups before writing `setgroups=deny`; write and reread exact singular maps; never call `setgroups` after `deny`. Model overflow post-unshare IDs and require they cannot become parent-map values. |
| `AT-EXEC-01` | trusted-launcher portable; `_run_one_tool`/`_namespace_owner`/`_final_mapping_check` | A registered CLOEXEC status channel reports setup errors and reaches clean EOF only on successful exec. No map read or input write occurs before EOF. Two complete stable final-map snapshots and generation/report equality precede the first input byte. Pre-exec Python maps, partial setup, status byte, timeout, drift, or missing mapping fail with an unopened input gate. |
| `AT-SECCOMP-01` | trusted-launcher portable; production seccomp assembler/install/probe path | Architecture check precedes syscall numbers. The policy covers the complete accepted socket, io_uring, namespace/process, mount/root, capability/acquisition, `prctl(PR_SET_SECCOMP)`, and `seccomp` routes. Every named denial is an actual modeled return observation, including wrong errno and unexpected success. `execve` is denied. `execveat` is not called “one-shot” unless `AT-EXEC-ONCE-01` below has an accepted mechanism. |
| `AT-EXEC-ONCE-01` | trusted-launcher portable; production exec gate and surviving outer owner | Prove one fixed pre-exec child, one expected `execveat` syscall with fixed fd/flags under retained identity, one successful exec EOF, and denial of every later `execve`/`execveat` attempt. A label, fd-number comparison alone, or a stateless allow rule does not pass. This test is blocked pending the architecture decision in “Execveat challenge.” |
| `AT-T2-OBS-01` | trusted-launcher portable; actual `_coordinate` result construction | Start every fact as `UNOBSERVED`. Feed independently mutable observations for user/PID/mount/network namespaces, PID 1, fd map, all five capability sets, groups, securebits, NNP, seccomp install/mode/denials, final maps, descendants, mounts, paths, checkout, and cleanup. A result is constructible only when every required fact is observed and exact. Literal/prefilled booleans and operation labels fail mutation testing. |
| `AT-T2-OBS-02` | same; namespace/capability/security observers | Namespace object identities differ from baselines and have the required ownership relation; child `NSpid`/metadata establishes PID 1. Effective/permitted/inheritable are read via `capget`; bounding and ambient are independently enumerated/read. Securebits and NNP are reread. Seccomp install success, mode, fixed-program digest, and real denial outcomes remain separate facts. |
| `AT-ROOT-01` | trusted-launcher portable and recovery portable; `_materialize_root` through cleanup | Write-ahead-register the root intent before `mkdir` and mount intent before mount. Fault before/after every create, mount, copy, readback, remount, and assignment. The surviving owner retains exact parent/mount-namespace authority and removes only exact owned state; foreign/replaced state is preserved and produces terminal uncertainty. |
| `AT-LIFE-01` | `test/outcome-two-lifecycle-portable.py`; closure helper, outer worker, namespace owner and PID-1 child spawn paths | Creation returns/registers pidfd plus release gate before child effects. Child remains blocked until PID/start-time/SID/PGID/executable identity and pending descriptor/mount/namespace authority are registered by the surviving outer owner. Fault before/after each registration must leave recovery authority or terminal uncertainty. |
| `AT-LIFE-02` | lifecycle portable; shared stop/reap implementation | Stable recursive descendant census; retained pidfds; identity revalidation before TERM and KILL; fixed monotonic TERM/KILL/reap deadlines; no blocking `waitpid(...,0)` or raw-PID signal; subreaper/adopted descendant reap; pidfd retained on timeout/mismatch. Cover EOF-live, PID reuse, identity drift, unexpected descendant, and lost reap ownership. |
| `AT-FD-ENUM-01` | lifecycle and trusted-launcher portable; both production descriptor snapshot methods | Open `/proc/self/fd` explicitly and parse bounded `getdents64` records through that exact fd. Exclude exactly the enumerator fd. Model a library-created duplicate/transient descriptor and require it cannot enter the snapshot. Success reaches `baseline | owned_outputs` and cleanup restores baseline. |
| `AT-FD-CLOSE-01` | sealing, lifecycle, recovery, and trusted-launcher portable; every launcher/closure fd owner | Every fd is an `OWNED -> CLOSED/TRANSFERRED/CLOSE_UNCERTAIN` lease. Before- and after-effect close faults are attempted once; a reused number is never touched; bundle loops clear each lease before the next close; primary plus all safe cleanup errors remain ordered; repeat after poison returns the same failure. |
| `AT-RECORD-01` | lifecycle and trusted-launcher portable; proc stat/children/maps and sandbox control parsers | Require requested PID, one bounded record, complete lexical fields through stat field 22, strict state and integer bounds; strict child records; strict message shape/version/sequence/cardinality and no trailing bytes. One-byte mutants reject with the intended parser code. |
| `AT-UNAV-01` | trusted-launcher and recovery portable; namespace owner -> tool owner -> bootstrap | Preserve typed `RuntimeLauncherUnavailable` with the exact primitive and no success facts. It may be returned only after proved cleanup. Cleanup uncertainty is a distinct terminal cleanup error; generic error, exit 1, exit 125, or success placeholder is forbidden. |
| `AT-ADAPT-BOOT-01` | trusted-launcher portable | Replace `_drive_fixed_bootstrap_with_adapter_for_tests` with primitive adapters entered by the real production bootstrap/source-admission state machine. Wrong bytes must be consumed by real authenticate/load operations, not an attack-name loop. |
| `AT-ADAPT-ISSUE-01` | trusted-launcher portable | Drive real `_WorkerIssuer`, `sendmsg`, `recvmsg`, `_consume_issuance`, descriptor reads, and acknowledgement/EOF through a socket primitive adapter. No prebuilt consumed outcome. |
| `AT-ADAPT-T2-01` | trusted-launcher portable | Drive real root, namespace-owner, boundary, exec, final-map, input, stop, and result state machines. Mutating any observation without raising at a label must still prevent success. |
| `AT-ADAPT-REC-01` | recovery portable | Crash the real authority-bearing inner worker at every write-ahead cut while a real surviving outer owner retains the modeled worker/helper/root/namespace authority. Recover/reap that transaction without retrying preparation. A harmless empty child is not sufficient. |
| `AT-FIXTURE-01` | all seven Python suites and Outcome Two fixtures | Closed manifests require unique IDs, production method, primitive fault, intended code, and cleanup domains. `declared == executed` is insufficient: each oracle has a branch-removal sentinel proving the named predicate. `same-inode`, `ambiguous-fingerprint`, `mapping-object-bound`, `double-close`, `unexpected-owned-child`, `spawn-after`, and `cleanup-after-poison` must hit their named production branches. |
| `AT-MAP-BOUND-01` | `test/outcome-two-mapped-closure-portable.py`; `_mapped_closure` | Construct 129 unique authenticated identities so rejection reaches the mapping-object bound, not fingerprint ambiguity. Ambiguous fingerprint independently uses two valid distinct expected identities and asserts its exact code. |
| `AT-READABLE-01` | static/accounting gate plus hostile review | Delete obsolete compatibility and transcript-player routes. No semicolon-packed field declarations, multiple fallible effects, or multiple cleanup decisions on one physical line. Exact per-file and aggregate gross highs pass without deletion credit. Human hostile review remains required because an AST line check alone cannot establish readability. |

## Execveat challenge

ADR 0088 says the child installs seccomp and then `execveat`s gzip/zstd, while also requiring seccomp replacement denial and no later execution/acquisition route. The rereviews correctly challenge the current unrestricted `execveat`, but “allow the fixed `execveat` once” is **not implementable by a stateless classic-BPF allow rule**:

1. seccomp filters are monotonic but not stateful counters;
2. filtering on fd 198 and `AT_EMPTY_PATH` permits repeated calls;
3. fd 198 is CLOEXEC only after successful exec, but seccomp cannot bind a later numeric fd to the consumed kernel object;
4. the workload can potentially recreate fd 198 through open/dup/reuse unless every such route is denied; and
5. those open routes are needed by the dynamic loader after a pre-exec filter is installed.

A second stricter filter installed after the dynamic loader completes would work conceptually, but unmodified gzip/zstd has no accepted hook at that point. The outer process cannot remotely install a filter in the already-execed child.

One plausible stateful design is a seccomp user-notification listener owned by the surviving trusted outer supervisor: the filter returns `USER_NOTIF` for exec, the supervisor permits exactly the first registered pre-exec `execveat` notification from the exact child/fd/flags and denies all later notifications. This is not yet a complete design. The listener fd exists only after the child installs the filter, so transferring ownership to the outer process needs an accepted mechanism such as qualified `pidfd_getfd` or one narrowly controlled post-install transfer; silently allowing `sendmsg` would create another supposedly one-shot rule. The design also needs a single-threaded pre-exec child, exact notification-ID validation, bounded listener lifecycle, fail-closed owner death, and the `AT-EXEC-ONCE-01` matrix. `SECCOMP_USER_NOTIF_FLAG_CONTINUE` has documented race concerns; continuation is defensible only if the first caller is still trusted, single-threaded, blocked, and has no competing mutator. This changes the production protocol and required-kernel primitive set and needs explicit architecture acceptance plus later native qualification. It cannot fit in four gross launcher lines.

Other acceptable architecture choices would be an explicitly accepted post-loader trampoline or a changed T2 execution contract. Merely allowing fixed fd numbers, leaving `execveat` unrestricted, or relabeling successful exec as `exec.blocked` is not acceptable.

**Gate conclusion for exec:** `AT-EXEC-ONCE-01` is impossible under the current stateless filter. ADR 0088 must clarify/authorize a stateful mechanism or change the one-shot claim before this finding can close.

## Proving T2 facts without overclaim

The correction must separate three evidence layers:

1. **Portable/model fact:** the real production state machine requests a primitive, consumes a typed observation, and cannot set a result fact from an absent, failed, wrong-errno, or cleanup-uncertain observation. `AT-T2-OBS-01/02` can prove this without native effects.
2. **Production transaction fact:** on Linux, the owner records successful syscall return values and exact readbacks. Namespace inode/ownership relations, child `NSpid`, capability words plus bounding/ambient enumeration, securebits, NNP, seccomp mode, denial results, stable final maps, and cleanup baselines are separate observations. No operation name is itself evidence.
3. **Native applicability fact:** only later same-head Jobs A–E can establish that the real supported kernel supplied those observations. A portable pass must not say the namespace, seccomp, mount, `map_files`, or cleanup primitive actually worked.

Some claims must also be narrowed:

- `no_acquisition_route` can mean only “every route in the accepted, exhaustively enumerated x86-64 policy table was denied or removed.” It cannot mean a proof about every present/future syscall or kernel bug.
- `namespaces_released` can prove that every **owned** process and namespace fd was reaped/closed and the initial namespace/mount baselines were restored. It cannot prove that no unknown foreign reference exists anywhere on the host.
- successful filter installation plus `PR_GET_SECCOMP == 2` does not reveal the installed BPF program. The owner must bind the exact bytes/digest passed to the successful install and separately observe representative/required denials.
- a typed unavailable result is valid only after cleanup facts are observed. If cleanup cannot be proved, the result is cleanup uncertainty, not unavailable.

Current `RuntimeQualificationResult` construction cannot meet this rule because it converts no-op labels into literal `True` values. Tests must initialize facts as `UNOBSERVED` and mutation-test each source observation.

## Every second-review finding mapped to acceptance tests

The table preserves each report's own finding ID, including overlapping findings. No row is treated as closed merely because another report described the same defect.

| Second-review finding | Required acceptance tests | Gate disposition |
| --- | --- | --- |
| `O2-R2-BOOT P0-1` forgeable ambient admission | `AT-ADM-01`, `AT-ADAPT-BOOT-01` | Production change required; current duck typing fails. |
| `O2-R2-BOOT P0-2` overclaimed T2, replacement policy, unbounded/raw lifecycle | `AT-SECCOMP-01`, `AT-EXEC-ONCE-01`, `AT-T2-OBS-01/02`, `AT-LIFE-02` | Blocked; one-shot exec needs an architecture decision. |
| `O2-R2-BOOT P1-1` held-byte loader cannot import `platform` | `AT-ADM-02` | Production loader change required. |
| `O2-R2-BOOT P1-2` maps race pre-exec child | `AT-EXEC-01` | Production exec barrier required. |
| `O2-R2-BOOT P1-3` dead parallel launcher adapters | `AT-ADAPT-BOOT-01`, `AT-ADAPT-ISSUE-01`, `AT-ADAPT-T2-01`, `AT-ADAPT-REC-01` | Existing four transcript players must be deleted/replaced. |
| `O2-R2-BOOT P1-4` credentials, packet cardinality, generation rows | `AT-ISSUE-02`, `AT-ISSUE-03`, `AT-ADAPT-ISSUE-01` | Production protocol correction required. |
| `O2-R2-BOOT P2-1` `/proc/self/exe` versus symlink spelling | `AT-ADM-03` | Compare authenticated object identity, not strings. |
| `O2-R2-LIFE P0-1` incomplete seccomp acquisition/replacement/exec policy | `AT-SECCOMP-01`, `AT-EXEC-ONCE-01`, `AT-T2-OBS-01` | Blocked on one-shot mechanism and real policy observations. |
| `O2-R2-LIFE P0-2` final-map race | `AT-EXEC-01` | Production barrier required. |
| `O2-R2-LIFE P1-1` registration after effects and outer cannot recover helpers | `AT-LIFE-01`, `AT-ADAPT-REC-01`, `AT-ROOT-01` | Production ownership protocol required. |
| `O2-R2-LIFE P1-2` descendants/identity/deadlines/reap incomplete | `AT-LIFE-02`, `AT-RECORD-01` | Shared exact process owner required. |
| `O2-R2-LIFE P1-3` launcher retries uncertain descriptors | `AT-FD-CLOSE-01` | Launcher lease conversion required. |
| `O2-R2-LIFE P1-4` post-unshare UID/GID capture | `AT-USER-01` | Production ordering correction required. |
| `O2-R2-LIFE P2-1` scripted claim generators | `AT-ADAPT-BOOT-01`, `AT-ADAPT-ISSUE-01`, `AT-ADAPT-T2-01`, `AT-ADAPT-REC-01` | Dead players must not remain as boundary evidence. |
| `O2-R2-LIFE P2-2` loose records and false poison fixture | `AT-RECORD-01`, `AT-FIXTURE-01`, `AT-FD-CLOSE-01` | Parser and fixture corrections required. |
| `O2-R2-TESTS P0-1` all-true T2 without observations | `AT-T2-OBS-01/02`, `AT-ADAPT-T2-01` | Production result shape/construction required. |
| `O2-R2-TESTS P1-1` launcher labels instead of production methods | `AT-ADAPT-BOOT-01`, `AT-ADAPT-ISSUE-01`, `AT-ADAPT-T2-01` | Current green suite supplies no acceptance. |
| `O2-R2-TESTS P1-2` empty-worker crash called recovery | `AT-ADAPT-REC-01`, `AT-LIFE-01` | Real surviving outer transaction required. |
| `O2-R2-TESTS P1-3` child pidfd/reap authority discarded | `AT-LIFE-02` | Production lifecycle correction required. |
| `O2-R2-TESTS P1-4` transient launcher fd enumerator | `AT-FD-ENUM-01` | Use exact getdents fd implementation. |
| `O2-R2-TESTS P2-1` dead/coupled/contradictory fixture predicates | `AT-FIXTURE-01`, `AT-MAP-BOUND-01` | Exact intended error is mandatory. |
| `O2-R2-TESTS P2-2` production schema gate outside corpus | `AT-REPORT-01` | Enter actual production schema gate. |
| `O2-R2-TESTS P2-3` compressed security flow | `AT-READABLE-01` | Cannot be corrected by further compression. |
| `O2-R2-SANDBOX P0-1` seccomp/namespace overclaim and incomplete policy | `AT-SECCOMP-01`, `AT-EXEC-ONCE-01`, `AT-T2-OBS-01/02` | Blocked as above. |
| `O2-R2-SANDBOX P1-1` identity map built from overflow IDs | `AT-USER-01` | Production ordering correction required. |
| `O2-R2-SANDBOX P1-2` no exec-completion gate | `AT-EXEC-01` | Production barrier required. |
| `O2-R2-SANDBOX P1-3` root/process cleanup not recoverable | `AT-ROOT-01`, `AT-LIFE-01/02`, `AT-ADAPT-REC-01` | Write-ahead exact authority required. |
| `O2-R2-SANDBOX P1-4` parallel T2 claim generator | `AT-ADAPT-T2-01` | Must drive actual production state machine. |
| `O2-R2-SANDBOX P2-1` unavailable collapsed; fixed Python symlink mismatch | `AT-UNAV-01`, `AT-ADM-03` | Two independent production fixes required. |
| `O2-R2-SANDBOX P2-2` unreadable compressed control flow | `AT-READABLE-01` | Requires readable replacement, not packing. |
| `O2-R2-HOL P0-1` `setgroups` after deny and no exec barrier | `AT-USER-01`, `AT-EXEC-01` | Both production defects must be fixed. |
| `O2-R2-HOL P0-2` asserted T2/cleanup facts | `AT-T2-OBS-01/02`, `AT-ROOT-01`, `AT-LIFE-02` | Observed conjunction only. |
| `O2-R2-HOL P1-1` sealed object is `O_RDWR`, issuer demands `O_RDONLY` | `AT-ISSUE-01` | Real issuance path currently cannot succeed. |
| `O2-R2-HOL P1-2` outer loses exact process/descendant authority | `AT-LIFE-01/02`, `AT-ADAPT-REC-01` | Retain/transfer authority on every failure. |
| `O2-R2-HOL P1-3` launcher retries uncertain fd numbers | `AT-FD-CLOSE-01` | Launcher lease conversion required. |
| `O2-R2-HOL P1-4` label interpreter coverage | `AT-ADAPT-BOOT-01`, `AT-ADAPT-ISSUE-01`, `AT-ADAPT-T2-01`, `AT-ADAPT-REC-01` | Delete obsolete players. |
| `O2-R2-HOL P1-5` producer calls one decoder twice | `AT-REPORT-01` | Three genuinely independent paths required. |
| `O2-R2-HOL P2-1` typed unavailable lost | `AT-UNAV-01` | Preserve type only after cleanup. |
| `O2-R2-HOL P2-2` compatibility/transcript surfaces overclaim | `AT-FIXTURE-01`, `AT-ADAPT-BOOT-01`, `AT-ADAPT-ISSUE-01`, `AT-ADAPT-T2-01`, `AT-ADAPT-REC-01`, `AT-READABLE-01` | Remove obsolete compatibility/player code rather than count it as evidence. |

## Impossible or presently unauthorized requirements

### 1. Correction while production is immutable

Every P0 and nearly every P1 above identifies production behavior. Under this task's explicit no-production-edit restriction, no such finding can be fixed. Test-only changes cannot make the production constructor unforgeable, change seccomp, add an exec barrier, preserve pidfds, alter uid-map ordering, reopen sealed objects read-only, or make results truthful.

### 2. Existing gross highs

Current measured additions and ADR 0088 highs are:

| Surface | Current | High | Margin |
| --- | ---: | ---: | ---: |
| parser | 306 | 320 | 14 |
| closure | 1,696 | 1,700 | 4 |
| launcher | 1,296 | 1,300 | 4 |
| schema | 134 | 260 | 126 |
| schema registration | 27 | 30 | 3 |
| runtime-closure portable | 336 | 350 | 14 |
| mapped-closure portable | 232 | 300 | 68 |
| sealing portable | 250 | 300 | 50 |
| lifecycle portable | 394 | 400 | 6 |
| recovery portable | 378 | 400 | 22 |
| runtime-report portable | 225 | 300 | 75 |
| trusted-launcher portable | 238 | 500 | 262 |
| TypeScript wrapper | 83 | 150 | 67 |
| fixture aggregate | 433 | 700 | 267 |
| **Trusted/portable subtotal** | **6,028** | **7,010** | **982** |

The margins are non-transferable. ADR 0088 expressly gives no deletion credit. Therefore deleting the obsolete `_T2_SEQUENCE`, four `_drive_fixed_*_with_adapter_for_tests` players, compatibility `_seal_source`, no-op labels, and duplicate decoder call is required for reviewability but does not authorize the many new readable production lines. A real issuer adapter, exec gate, stateful exec policy, transactional root owner, observed T2 result builder, and exact lifecycle owner cannot be implemented in eight total production lines.

**A new ADR/high is mandatory before production correction.** Repacking the work into semicolon lines, tests, fixtures, schema, or workflow would violate ADR 0088.

### 3. Pure-Python “unforgeable” admission

An underscore method, exact class check, random process-local token, module name, stack inspection, or object identity is inspectable/forgeable by ambient code already executing in that Python process. The accepted security boundary must rely on source admission excluding such code and on a live one-shot kernel endpoint/process topology. If the requirement instead means resistance to arbitrary code already executing inside admitted T1, it is impossible in the current Python process model and must be narrowed.

### 4. Exactly-once exec under the current seccomp design

As detailed above, stateless cBPF cannot consume an allow rule. This requirement is impossible without an accepted stateful broker or a post-loader installation mechanism.

### 5. Real T2 proof before native execution

Portable tests cannot establish real namespace, mount, capability, seccomp, proc, map-files, pidfd, or kernel cleanup facts. They can establish only that production asks for and truthfully consumes those observations. Demanding real T2 facts before allowing Jobs A–E would be circular. The pre-native review must sign off implementation shape and model hostility without promoting it to native evidence; Job E later establishes same-head kernel applicability.

### 6. Universal absence claims

“No acquisition route” and global namespace absence are not finitely observable as universal host facts. They must be scoped to the accepted enumerated syscall/descriptor/filesystem policy and exact owner authority. Wider wording is impossible to prove and must not become a boolean.

## Required correction order after new authority

1. Accept a superseding ADR for a stateful one-shot execution mechanism (or changed execution contract), revised result semantics, and readable closure/launcher highs.
2. Delete obsolete compatibility and transcript-player code; do not retain it as narrow “coverage” of the security boundary.
3. Correct admission loading, fixed-Python identity, read-only sealed references, issuer cardinality, and independent schema/codec paths.
4. Introduce shared fd/process leases, exact getdents snapshots, preregistration, bounded descendant reap, and write-ahead root/namespace ownership.
5. Correct user/group-map ordering and implement the synchronized exec/final-map/input gate.
6. Construct T2 facts from typed observations and preserve unavailable versus cleanup uncertainty.
7. Replace all four label players with primitive adapters over those production state machines and make every fixture predicate exact.
8. Run the seven portable suites, optimized rejection, AJV/schema checks, static quality/accounting checks, and a fresh exact-head hostile rereview.
9. Only after zero unresolved P0–P3, seek separate authority for native A–E and later thin integration.

## Audit checks and non-claims

Static inspection confirmed the reviewed production and test counts above and the current dead-player call graph. No portable suite was rerun because this task changed no implementation/test behavior and the existing green runs are explicitly non-accepting for the findings above. No native or privileged primitive, compression tool qualification, namespace, mount, seccomp, `map_files`, network, provider, workflow, cloud, or deployment action was invoked.

This gate supplies no native readiness, Outcome 2 completion, AWS/provider/OpenTofu/deployment, production, release, or issue-closure authority.

O2-FIX2-AUDIT COMPLETE
