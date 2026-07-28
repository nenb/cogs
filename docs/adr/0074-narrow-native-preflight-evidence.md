# ADR 0074: Narrow native preflight evidence to native primitives

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct the evidence architecture after `/tmp/adr73-final-code-review.md`. Supersede ADRs 0071–0073 only where they require complete platform-independent crash, resource-accounting, or static-mutation matrices inside `native-runtime-preflight`. Keep that job for Linux-amd64, namespace-root-sensitive production primitives unavailable on Darwin or QEMU; require the portable generated/fault suites separately; simplify only the exact five excluded workflow/test files; retain ADR 0073's maxima without deletion credit and target a smaller implementation. Production code, production caps, schema contract, events, acquisition, and cloud boundaries do not change.

## Context

The final ADR 0073 precommit review in `/tmp/adr73-final-code-review.md` found no P0 or P3 and confirmed the native sandbox, anonymous output, exact selector, genuine gzip/zstd child, low/high descriptor, PDEATH, production readability, and retained cap foundations. It kept the gate closed because the implementation did not satisfy ADR 0073's genuine failed-child `execve`-fresh CLI lifecycle, complete transitive reservation/reconciliation and per-internal-operation deadline architecture, final tracked-schema condition, or canonical-source semantic mutation framework.

Those findings expose a layering error. Failed-settlement lifecycle, ownership, journal, report, export, crash/recovery, parser, schema, and budget behavior are portable production contracts. Requiring all of their generated and injected matrices to execute again as namespace root on native Linux does not make them more authentic. Requiring a companion to instrument, reserve, authenticate, and time every opaque internal production syscall turns the harness into a second implementation of production resource ownership. Canonical source digests plus rebound semantic mutation tests similarly test a bespoke static framework rather than the production behavior.

The native job has a narrower legitimate purpose: prove genuine Linux-amd64 and namespace-root-sensitive primitives that Darwin and the available Linux/amd64 QEMU envelope cannot prove. QEMU returned `ENOSYS` for the required `close_range`; Darwin cannot provide Linux `/proc`, `PR_SET_PDEATHSIG`, Linux namespace/chroot behavior, or the relevant `O_TMPFILE` publication semantics. The evidence architecture should keep those native facts in the hardened job and keep platform-independent generated/fault qualification in ordinary portable tests.

## Decision

### Exact correction ancestry

The exact implementation predecessor is `96c244d2353903bfae0d7487916ed6987b8fa485`. It is the history-preserving integration merge whose first parent is `a4a4c6f5a6be5c2eb0101a7c365e20cfe796607b` and whose second parent is accepted ADR 0073 commit `56744a26ca9f8e8eaa5bf568f131abe081c1519f`.

Implementation must start at exactly `96c244d2353903bfae0d7487916ed6987b8fa485` and integrate the exact accepted commit containing this ADR by a history-preserving merge before any implementation commit. That integration merge must have `96c244d2353903bfae0d7487916ed6987b8fa485` as first parent and the accepted ADR 0074 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from this documentation branch is prohibited. Final implementation head must descend from both exact parents.

### Native preflight proves only native-sensitive production primitives

The selected `native-runtime-preflight` route must remain the exact hardened same-repository pull-request, quality-first, Ubuntu 24.04 Linux-amd64 route established by ADRs 0071–0073. The runner identity/group drop, descriptor closure, `no_new_privs`, fresh user/network/PID/mount namespaces, exact mount verification, terminal chroot, namespace UID/GID 0 with all capability sets empty, no host socket or network route, and descriptor-backed anonymous output comparison remain mandatory.

Inside that envelope, native qualification is complete when it proves all of these production facts:

1. Genuine `close_range` succeeds over deliberately inherited low- and high-numbered descriptors. `ENOSYS`, fallback, descriptor enumeration as a substitute, uncertainty, or any leak fails.
2. Both fixed `/usr/bin/gzip` and `/usr/bin/zstd` genuinely execute through the production archive child. For each executable, the production route authenticates the post-loader, pre-input state from Linux `/proc`, performs the genuine mapped-closure path before releasing archive input, and proves the mapped/proc descriptors and deliberately inherited descriptors are closed.
3. The genuine production child arms `PR_SET_PDEATHSIG`; Linux `/proc` identity binds the intended parent and child across the handshake; parent death before and after authenticated release produces the required death/reparent state; and bounded wait/reap and `/proc` observations prove exact identity absence with no surviving descendant.
4. The production anonymous-download/publication route uses genuine `O_TMPFILE`, proves link count zero before publication, namespace-root UID/GID ownership and the exact required mode transitions, publishes the same authenticated inode through the production mechanism, and proves the exact final publication identity and cleanup.
5. The complete namespace/chroot isolation and exact anonymous-output protocol are dynamically proved, including pre-launch unlink and link-count-zero state, child fd 1/2 only for output, byte-exact descriptor-backed comparison, and post-child descriptor-only reclamation.

These are the complete native matrix. The native route need not execute the complete platform-independent owner/journal/report/export crash matrix, every injected production fault, every parser/schema/budget case, or the failed/non-terminal recovery lifecycle. It need not intercept, count, reserve, reconcile, alarm, or mutate every internal production syscall. Native checks may use focused seams only to reach and observe the genuine primitives above; mocks or static source assertions cannot substitute for those primitive outcomes.

The exact selector remains `COGS_REQUIRE_NATIVE_RUNTIME_PREFLIGHT_V1=1`. The process marker remains exactly `completion Kata process LINUX AMD64 QUALIFIED matrix passed`, and the candidate marker remains exactly `stage2 phase-a candidate portable tests passed`. The fixed outer protocol may accept either marker as native evidence only from its corresponding exact-selector invocation and only after every applicable native fact above and all companion-created resource cleanup have succeeded. A marker from an absent, duplicate, empty, non-exact, portable, skipped, partial, fallback, `ENOSYS`, gzip-only, or residue-bearing route grants no native evidence.

### Portable generated and fault qualification remains mandatory

Ordinary portable tests remain a separate mandatory gate. Without requiring the native selector, they must continue to exercise production ownership, journal, report, export, crash, recovery, parser, schema, and budget behavior, including generated success/failure fixtures and applicable before-/after-effect fault cases. Production recovery behavior for failed and non-terminal settlements remains mandatory there. It no longer must be created by a genuine failed native archive child or recovered by an `env -i`/`execve`-fresh CLI inside the native job.

Portable process replacement, generated fixtures, injected seams, fresh imports/processes where useful, and direct behavior/schema assertions are valid for these platform-independent contracts. The later separately authorized authentic runtime/lifecycle discovery remains responsible for production-created durable lifecycle evidence in a real lifecycle. This ADR neither performs nor authorizes that discovery and does not weaken any prerequisite for it.

The TypeScript companions must continue to assert the exact workflow selector, isolation, fixed executable routes, primitive ordering, output protocol, portable-suite invocation, resource limits, and prohibited acquisition/network/fallback behavior. Direct structural and behavioral assertions are sufficient. ADR 0073's canonical complete-source SHA-256 selections, ordinary digest-mismatch gate, rebound-digest mutation cases, and actual-semantic-validator mutation framework are removed requirements and may be deleted. No replacement mutation framework or canonical source digest is required.

### Bounded harness resources

For each companion invocation, every generated fixture has a fixed declared size no greater than 64 KiB, and aggregate generated fixture bytes are no greater than 1 MiB. No more than 16 companion-induced temporary pathnames and no more than 16 child processes may be simultaneously live. Each explicit harness operation that can block—such as a harness read, write, selector wait, child wait/reap, or settlement wait—must have its own monotonic bound no greater than 30 seconds. The exact outer timeout remains 240 seconds per companion.

These bounds apply to explicit harness fixtures and operations. They do not require transitive instrumentation of opaque production-internal syscalls, per-syscall reservations, descriptor/open-description ledgers, canonical source accounting, or a syscall mutation framework. Fixed size/count assertions, bounded helpers, process/path inventories, and final zero-residue checks are sufficient. Unbounded harness I/O, wait, polling, retry, fixture generation, pathname creation, or child creation remains prohibited.

### Exact five-file simplification and retained maxima

Only these exact five files may change under this ADR:

| File | Authorized simplification/correction | Retained gross-addition maximum from `18f2644` |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | Retain the hardened native envelope and exact anonymous output; remove no native-sensitive proof. | **280** |
| `test/aws-stage2-completion-kata-process.py` | Narrow selected native work to genuine gzip/zstd mapped closure, low/high `close_range`, PDEATHSIG, `/proc` identity/reaping, and bounded cleanup; retain portable process/recovery behavior separately. | **750** |
| `test/aws-stage2-completion-kata-process.test.ts` | Replace digest/mutation architecture with direct assertions for the narrow native route and mandatory portable route. | **80** |
| `test/stage2-phase-a-candidate.py` | Narrow selected native work to genuine `O_TMPFILE` root/mode/link-count/publication and cleanup; retain portable ownership/journal/report/export/crash/recovery/schema/budget coverage separately. | **850** |
| `test/stage2-phase-a-candidate.test.ts` | Replace complete crash/resource/digest mutation assertions with direct native-boundary and portable-suite assertions. | **600** |
| **Exact five-file aggregate** |  | **2,560** |

The ADR 0073 maxima remain non-transferable hard ceilings, not targets or reserves. Implementation is expressly authorized and expected to simplify and delete obsolete harness, ledger, digest, mutation, and native-duplicate matrix code. The preferred target is below the ADR 0073 reviewed additions of 234/750/61/841/458 and 2,344 aggregate wherever removal of the superseded architecture permits. Deletion, movement, replacement, or removal creates no credit against another file, a retained production maximum, or the aggregate; every retained/added replacement line is still accounted by the no-rename addition column from exact `18f26441b6115091233d0c4cd44ced8f058d014f` to final head.

No sixth file may be modified under ADR 0074. No production module, production runner, budget script, qualification module, runtime module, schema contract, candidate workflow, package file, lockfile, fixture file, or new test file may change. The retained production highs remain candidate runner 520, budget script 30, qualification 450, process 1,000, runtime 800, schema 340, and aggregate 3,310, all measured from exact `84b30d30b3307f1c5222dd9e50dfa755cdee673a`. Tracking the already-reviewed Phase B schema and prior production implementation in the final commit remains required under prior authority, but ADR 0074 grants no content change to either.

## Final evidence and gates

One exact final implementation commit must contain all prior reviewed implementation files, the bit-for-bit final Phase B schema as a tracked file, and the exact five-file correction. The exact final head must be clean: no modified, generated, ignored evidence residue relevant to the implementation, or untracked file may remain. It must descend through the required first/second-parent integration and pass the complete ordinary portable checks. No native run is authorized by this documentation-only ADR; native evidence remains unavailable until a separately permitted execution of the retained job succeeds for the exact head.

Before any result can be relied upon, obtain a clean independent hostile review of exact no-rename range `84b30d30b3307f1c5222dd9e50dfa755cdee673a..FINAL_HEAD`, with separate exact-five-file accounting from `18f26441b6115091233d0c4cd44ced8f058d014f..FINAL_HEAD`. Review must verify ancestry, exact five-file-only ADR 0074 changes, tracked schema, clean final head, unchanged production code/caps, mandatory separate portable suites, the complete narrow native primitive set, exact selector/markers after those facts, simplified resource bounds, retained sandbox/output/acquisition prohibitions, and no unresolved P0–P3 finding. Review must not reinstate the superseded native full crash matrix, transitive syscall instrumentation, genuine failed-child exec-fresh CLI recovery, canonical digest, or semantic mutation requirements. Any later change invalidates signoff.

Until the required final commit, checks, separately permitted exact-head native result, and clean review exist, `native-runtime-preflight` is not valid evidence, ADR 0069's sole local actual-size execution remains ineligible, and `phase-b-runtime-discovery` remains closed.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0073 trigger, same-repository restriction, namespace/capability boundary, event count, consumption rule, timeout, schedule, owner model, report shape, retry/fallback prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. The conservative projection remains `33,344 < 34,000`; the 32,000 preferred target, 34,000 hard cap, and 656-line margin remain unchanged and grant no implementation authority.
