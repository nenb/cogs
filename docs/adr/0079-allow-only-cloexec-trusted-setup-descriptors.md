# ADR 0079: Allow only close-on-exec trusted setup descriptors

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Amendment scope: Correct only ADR 0076's exact-open-set assertions for the trusted Bash namespace PID 1 after native execution at exact head `d53b1165f7a66170d3fcfd80d77e04e75f6f7359` failed with the fixed `launcher-fds` classification. An independent synchronous observer enumerates its quiescent parent through `/proc/<ppid>/fd` and inspects every parent's `F_GETFD`/`FD_CLOEXEC` state through the corresponding parent `/proc` fd handles. Before the checkout bind, authenticated fd 3 is the sole descriptor at or above 3 allowed without `FD_CLOEXEC`; any other high descriptor is accepted only when it is close-on-exec, fixed trusted-shell-owned state, and neither a socket, namespace handle, nor checkout identity. After fd 3 closes, every descriptor at or above 3 must be close-on-exec. Namespace PID 1 then immediately terminally execs chroot, the kernel closes all such setup descriptors, and the in-chroot launcher/test independently proves its own exact inherited descriptor set and absence of an inherited socket. Only CI and the two existing TypeScript static companions may change under retained highs 360/80/600. No production, checked-in Python, schema, cap, run, event, acquisition, cloud, or AWS boundary changes.

## Context

The ADR 0078 implementation at exact clean head `d53b1165f7a66170d3fcfd80d77e04e75f6f7359` successfully moved checkout-fd creation after permitted `sudo --close-from=3`. The fixed root Python launcher authenticated the checkout, created inheritable fd 3, proved its own exact descriptor table, and terminally executed the retained `setpriv`/`unshare`/trusted-Bash chain. Native execution then failed before the bind with the fixed `launcher-fds` classification.

That result does not identify an additional inherited authority channel. Bash may retain interpreter-internal descriptors at or above 3 while executing the fixed trusted setup text. Such descriptors can exist in namespace PID 1 even though they carry `FD_CLOEXEC` and therefore cannot survive its required terminal exec. ADR 0076's observers instead required the Bash parent names to be exactly `0,1,2,3` before bind and exactly `0,1,2` after closing fd 3. That requirement confuses a transient, close-on-exec interpreter implementation detail with a descriptor that can reach checked code.

Broadly allowing high descriptors, trusting Bash's current allocation pattern, scanning only the observer's own table, or checking only `/proc` symlink text would weaken the handoff. The narrow security property is that fd 3 is the only high descriptor capable of surviving setup execs before its authenticated use; after fd 3 closes, no high descriptor can survive the immediate chroot exec. Independent observation of the quiescent parent, object identity/type rejection, and an exact in-root inherited-table proof preserve that property without depending on Bash exposing an exact numeric open set.

## Decision

### Exact correction ancestry

The exact implementation predecessor is current clean branch head `d53b1165f7a66170d3fcfd80d77e04e75f6f7359` on `feat/issue42-candidate-tar-remediation`. It contains the exact native `launcher-fds` failure classification and descends through the required accepted ADR 0078 integration. If that implementation branch advances before integration, a new ADR or explicit accepted amendment must bind the replacement exact head; an unrecorded moving-head substitution is prohibited.

Implementation must start at exactly `d53b1165f7a66170d3fcfd80d77e04e75f6f7359` and integrate the exact accepted commit containing this ADR by a history-preserving merge before the correction commit. That integration merge must have `d53b1165f7a66170d3fcfd80d77e04e75f6f7359` as first parent and the accepted ADR 0079 commit as second parent. Cherry-picking, squashing, rebasing either side, substituting an equivalent tree, or beginning implementation from this documentation branch is prohibited. Final implementation head must descend from both exact parents.

### Narrow supersession of exact Bash open sets

ADR 0079 supersedes only ADR 0076's requirement, retained by ADR 0078, that trusted Bash namespace PID 1 have the exact descriptor-name set `0,1,2,3` before bind and exact set `0,1,2` after closing fd 3. It does not supersede the post-sudo root launcher's exact `0,1,2,3` proof, fd 3's authentication or sole-checkout-reference property, the exact no-canonical bind, child reaping, target authentication, fd-3 closure, immediate terminal chroot exec, or checked-code inherited-empty boundary.

Fd 0 remains the authenticated `/dev/null` input, and fd 1 and fd 2 remain the subprocess-created references to the retained anonymous output open description. Before bind, fd 3 remains the exact authenticated `O_PATH|O_DIRECTORY|O_NOFOLLOW` checkout descriptor, with `FD_CLOEXEC` clear, the expected device/inode/directory identity, the overflow-mapped nonzero runner ownership, and no alias. It must be the sole descriptor at or above 3 without `FD_CLOEXEC`. A missing fd 3, changed identity, extra checkout reference, or any other non-close-on-exec high descriptor fails closed.

Bash interpreter-internal descriptors at or above 3 are tolerated only as transient trusted setup state. Every such descriptor must have `FD_CLOEXEC` set and must be attributable to the fixed trusted shell execution rather than caller data or checked-out code. Its kernel object and `/proc` target must not be a socket, network endpoint, namespace handle of any kind, checkout directory or alias, checkout ancestor, old-root authority, proc namespace handle, credential, secret, or caller-selected file. Object identity must not equal fd 3 or any authenticated checkout identity. Socket inode syntax, `stat` socket type, namespace-handle syntax or type, duplicate checkout device/inode, an unreadable or unstable identity, an unsupported object class, or inability to prove `FD_CLOEXEC` is a terminal failure. This is not a general descriptor allowlist and does not authorize retained pipes, files, directories, devices, or anonymous inodes from outer callers.

### Independent parent observers

Each descriptor proof is performed by a newly started isolated trusted Python observer while its parent Bash namespace PID 1 is quiescent and waiting. The observer derives the parent with `os.getppid()`, requires it to be namespace PID 1, enumerates the parent's numeric descriptors from a stable `/proc/<ppid>/fd` directory handle, and inspects each corresponding parent fd handle and fdinfo record. It must inspect the per-descriptor `F_GETFD` state and classify the exact `FD_CLOEXEC` bit; it may not infer safety from descriptor number, observer inheritance, symlink text alone, `F_GETFL` alone, or an allow-on-error default. Enumeration, flag inspection, and identity inspection must describe one stable parent table; disappearance, replacement, duplicate record, malformed flags, race, or inability to inspect any entry fails closed.

The observer may open descriptors only in its own process. It must not mutate, duplicate into, close, or otherwise normalize the parent's table. PID 1 synchronously waits for and reaps it, and no observer survives. The pre-bind observer additionally retains every ADR 0076 one-ID map and overflow-ownership proof and exact fd-3 identity/flag check. Its only change is replacing exact parent-name equality with the narrow rule above.

After the no-canonical bind, both exact target authentications, the read-only `nosuid,nodev,noexec` remount, all setup children that used fd 3, and every other retained mount verification, Bash PID 1 closes fd 3 itself. The second observer then applies the same stable independent parent-table inspection and requires every extant descriptor at or above 3 to have `FD_CLOEXEC` set and satisfy the same fixed trusted-shell-owned, no-socket, no-namespace, no-checkout identity restrictions. Any non-close-on-exec descriptor at or above 3 fails, regardless of number, apparent harmlessness, target text, ownership, or intended later closure.

### Terminal exec and independent in-root proof

After the second observer exits successfully and PID 1 synchronously reaps it, PID 1's immediate next action remains the terminal `exec /usr/sbin/chroot ...`. No command, substitution, diagnostic, scan, helper, close loop, pathname operation, or fd-opening action may intervene. The kernel must close every tolerated high setup descriptor because each has `FD_CLOEXEC`; none may cross the chroot exec. This kernel exec transition, not a best-effort shell close loop, is the authorized disposal mechanism.

The fixed in-chroot launcher/test must independently inspect its own inherited descriptor table before opening evidence or installing the filter and prove it is exactly fd 0, fd 1, and fd 2. It must also inspect those objects and prove that no inherited descriptor is a socket. The selected in-chroot test entry must independently retain the same exact-inherited-fds/no-inherited-socket assertion before creating any descriptor for its bounded native primitive tests. A transient descriptor used to enumerate `/proc/self/fd` must be handled without weakening exactness, and a self-scan may not substitute for either parent observer. Any inherited fd at or above 3 or any socket identity fails before checked test behavior. Descriptors deliberately created after that entry proof for the retained bounded native primitives remain governed by ADR 0074 and do not weaken the inherited boundary.

The post-sudo launcher still has exact fds 0–3 before it terminally execs `setpriv`; `sudo --close-from=3`, empty environments, exact one-ID maps, fixed trusted source, no checkout pathname in Bash, and no broad descriptor inheritance remain unchanged. No socket, namespace, checkout, or shell-internal descriptor is newly permitted to reach chroot or checked code.

### Exact authorized files and retained highs

Only these exact implementation surfaces are authorized:

| File | Authorized correction | Binding maximum |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | Replace only the two trusted-Bash exact-open-set observer assertions with stable independent parent fd/`F_GETFD` classification, enforce the pre/post close-on-exec and object restrictions, and add the exact independent in-root inherited-fd/no-socket proof. | Retained **360** gross additions from `18f2644` |
| `test/aws-stage2-completion-kata-process.test.ts` | Require the narrowed parent-observer, terminal kernel-close, in-root exact-fd/no-socket lifecycle and reject any non-close-on-exec extra or broad allowlist. | Retained **80** gross additions from `18f2644` |
| `test/stage2-phase-a-candidate.test.ts` | Require the same exact observer and terminal-exec lifecycle while retaining all mount, checkout, and sandbox boundaries. | Retained **600** gross additions from `18f2644` |

The three highs remain non-transferable no-rename gross additions from exact `18f26441b6115091233d0c4cd44ced8f058d014f`. ADR 0077's checked-in Python highs of 750 and 850 and exact-five-file aggregate high of 2,640 remain unchanged. Deletion, movement, replacement, consolidation, or removal creates no credit. Ordinary readable state, object classification, race handling, and failure transitions remain mandatory.

No checked-in Python file, production module, production runner, schema, package file, lockfile, deterministic fixture, `.gitleaksignore`, Gitleaks configuration, workflow other than `.github/workflows/ci.yml`, or new file may change. No behavior beyond this descriptor-observer correction and the corresponding inherited-boundary proof is authorized.

## Evidence and gates

Portable static companions and final hostile review must prove: the post-sudo root launcher's retained exact fds 0–3; synchronous observers with parent namespace PID 1; stable enumeration through parent `/proc` fd handles; per-parent-descriptor `F_GETFD`/`FD_CLOEXEC` inspection rather than self-table inference; exact authenticated non-close-on-exec fd 3 before bind; rejection of every other non-close-on-exec high fd; fixed trusted-shell ownership and rejection of socket, namespace, checkout, checkout-ancestor, old-root, secret, and caller-selected identities; fd-3 closure only after its last authenticated use; all remaining high fds close-on-exec; observer exit and reaping; and immediate terminal chroot exec with kernel closure and no intervening action.

Review must separately prove the in-chroot launcher/test's independent exact fds 0–2 and no-inherited-socket checks occur before either opens setup evidence or creates bounded test descriptors. It must reject exact-set dependence on Bash internals, a self-scan in place of parent observation, symlink-text-only classification, `F_GETFL` in place of `F_GETFD`, unstable `/proc` races, broad object or descriptor allowlists, ignored inspection errors, delayed closure, shell close loops as the terminal guarantee, any non-close-on-exec extra, and any descriptor or socket inherited by checked behavior.

The final implementation commit must descend through the required first/second-parent integration, retain all prior reviewed implementation and the tracked Phase B schema, be clean, pass ordinary portable checks, and remain within exact highs 360/80/600 and aggregate 2,640. Checked-in Python, production, schema, Gitleaks bytes, caps, and every unauthorized surface must be unchanged from the predecessor. Any later change invalidates signoff.

## Retained boundaries and consequences

This accepted documentation-only correction authorizes no workflow run, event, attempt, rerun, replacement, acquisition, archive download, artifact, upload, candidate, actual-size execution, rootfs, KVM, container, containerd, Kata lifecycle, workload, production use, campaign, release, deployment, credential, cloud action, AWS API/provider, OpenTofu, or other AWS action.

Every non-conflicting ADR 0065–0078 trigger, same-repository restriction, event count, consumption rule, timeout, schedule, owner model, report shape, retry/fallback prohibition, production prohibition, workload ordering, step-5 stop, cloud stop, and AWS boundary remains unchanged. No cap changes: workflow/TypeScript highs remain 360/80/600, checked-in Python highs remain 750/850, the exact-five-file aggregate remains 2,640, the Phase B aggregate remains 3,310, and the conservative global projection remains `33,344 < 34,000`. The 32,000 preferred target, 34,000 hard cap, and 656-line margin remain unchanged and grant no implementation authority.
