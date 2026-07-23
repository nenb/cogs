# ADR 0040: Use direct fixed rootfs materialization

- Status: Accepted
- Date: 2026-07-23
- Decision owner: Nick Byrne
- Acceptance: Accepted by the delegated project lead under Nick Byrne's standing delegation to continue autonomously and make project decisions without waiting, after hostile review of the direct-materializer replan.

## Context

ADR 0038 authorizes local-only implementation of the bounded issue #42 Stage 2 completion campaign. It fixes the Debian 13 slim OCI inputs, the Debian snapshot, the exact ten-package candidate set and order, inert maintainer scripts, deterministic two-build output, later runtime-closure qualification, and a separate future cloud gate. Its package section permits extraction with fixed `dpkg-deb -x`.

ADR 0039 changes only ADR 0038's numeric Stage 2 completion cap. It does not select or broaden a rootfs composition mechanism.

Merged R1 at `a653a12ea0aba151050b9b082687721816f1458d` now provides a stricter semantic boundary than existed when ADR 0038 was accepted:

- `PreflightedTar` owns the exact expanded tar bytes;
- each `MaterialRecord` separates literal symlink text, resolved graph paths, hardlink targets, archive-size semantics, metadata, and regular content identity;
- unsupported types, sparse entries, whiteouts, unsafe paths, duplicate paths, link escape, and paths below symlinks fail before materialization;
- the OCI base and exact ten package payloads are combined in fixed order with directory-only overlays; and
- seven exact generated transitions produce one final immutable entry graph while retaining all unmentioned source state.

The subsequently proposed external package-extractor route would interpret the same payloads a second time through root-executed `dpkg-deb`, tar, and xz. Making that route safe required an external image and tool contract, copied helpers, sealed memfds, exact descriptor inheritance, process supervision, PID namespace ownership, timeout and descendant teardown, and an additional real extractor gate. The rootfs still needed a project-owned fd-relative writer, postwalker, ownership ledger, cleanup, and deterministic publication afterward.

A hostile review found that direct materialization from the already accepted immutable payload model has the smaller incremental trusted computing base. It removes the second archive interpreter and all child-process authority while preserving the filesystem writer and verification work that deterministic output already requires.

This is a trust-boundary change. It must be explicit rather than inferred from ADR 0038's permissive wording or introduced silently through implementation.

## Decision

Use one project-owned, fixed, no-argument, fd-relative materializer for issue #42 rootfs composition.

This ADR supersedes **only** ADR 0038's rootfs composition mechanism and the later review interpretations requiring fixed `dpkg-deb -x` for rootfs composition. It does not change ADR 0038's immutable inputs, package set or order, runtime workloads, qualification requirements outside composition, cloud gate, cost/time limits, cleanup standards, evidence boundary, or non-claims. ADR 0039's preferred and hard cumulative caps remain unchanged.

The materializer consumes the exact immutable preflight results and final rootfs plan once:

1. stable-read and verify the accepted 16-file cache and artifact contract;
2. preflight the exact OCI base and all ten exact package archives;
3. retain each full package byte string, all three ar-member identities, exact data member, and its owning `PreflightedTar` payload;
4. construct and revalidate the complete fixed final root and entry graph;
5. create each final graph path exactly once through the fixed writer; and
6. authorize the result only after a complete independent postwalk matches the expected graph and root policy.

There are no package extraction stages, stage merges, external extractor, subprocess, executable/helper selection, memfd, supervisor, pidfd, PID namespace, package script, package-database mutation, or fallback selector in rootfs composition.

The mechanism is still materialization of accepted archive semantics. “Direct” means no external or staged package extractor; it does not mean archive semantics disappear.

## Exact immutable semantic authority

### Full package and payload ownership

The direct build-input model must retain, per independent build:

- the exact artifact-contract byte digest;
- a fresh complete identity/hash snapshot of all 16 cache files;
- deeply frozen scalar copies of all ten exact package rows;
- each package's exact complete `.deb` bytes;
- the ordered member identity tuple for `debian-binary`, `control.tar.xz`, and `data.tar.xz`;
- the exact data-member name; and
- the `PreflightedTar` that owns the expanded data bytes and records.

Control archives remain strictly parsed for exact package, version, and architecture metadata. Maintainer scripts and service-manager behavior remain inert and are never copied into the final graph unless they are ordinary data-payload entries already represented there.

Regular content access must be owner-bound. A `MaterialRecord` may select bytes only from its exact owning `PreflightedTar` and record index or an equivalently strict owner token. Dataclass value equality with a foreign equal record is insufficient authority.

Immediately before the first filesystem write, production must revalidate the complete fixed input, root policy, source order, package order, transition set, graph, record ownership, and content hashes. No caller-created plan, record, archive, root, path, or cache location may reach production orchestration.

### Exact root-directory policy

R1 intentionally omitted archive `./` records from `RootfsPlan.entries`. The direct route must extend the immutable model with an explicit root identity rather than infer it from a missing graph entry or leave the retained root private 0700.

The exact OCI `./` record is authoritative for the final rootfs directory:

```text
kind:  directory
uid:   0
gid:   0
mode:  0755
size:  0
mtime: 1782172800
```

Every one of the ten package `./` records must be present and must be exactly:

```text
kind: directory
uid:  0
gid:  0
mode: 0755
size: 0
```

A package root record validates package shape only. It never overlays or changes the authoritative OCI root identity. Any missing or drifting root record is input drift and fails before writing.

The writer creates the retained root temporarily as root-owned mode 0700, writes only beneath its held descriptor, and finalizes it after descendants to exact UID 0, GID 0, mode 0755, mtime 1782172800, empty xattr/ACL state, and the approved device/mount policy. Postwalk, canonical output, retained-root verification, and publication must include this root identity separately from entry records.

### Final graph authority

The writer consumes only the final immutable `RootfsPlan` plus the explicit root identity. Overlay behavior remains entirely in planning:

- OCI base first;
- exact ten packages in contract order;
- matching directory overlays only;
- no nondirectory replacement or path beneath a symlink;
- seven exact account/configuration transitions; and
- default retention of every unmentioned source entry and source mtime.

The filesystem writer must not replay base/package overlays, implement whiteouts, replace existing files, normalize broad path categories, create package installation state, or infer a different graph.

## Fixed production boundary

Production may expose only fixed no-argument modes that resolve the accepted contract, cache, private state root, operation root, and recovery target internally. No API or CLI may accept an archive, package, plan, record, source, destination, root path/fd, ownership, mode, timestamp, command, executable, helper, environment, or recovery name.

Internal fd/record adapters may exist for tests. They do not create caller-selectable production behavior.

The direct route has exactly one writer and one walker. The walker is reused for creation checks, final postwalk, canonical manifest input, accepted-root verification, and cleanup observations. There is no alternate writer, external-tool fallback, path-based fallback, or host tar.

## Filesystem materialization contract

### Operation ownership

Use one exact root-owned single-link regular lock inode beneath the fixed state parent. Each operation is one new direct child with an unpredictable non-output name, root-owned mode 0700, exact sentinel, expected parent/device identity, and one strict fsynced identity ledger.

Set and verify the fixed umask before creation. Reject wrong owner, mode, type, link count, device, mount policy, sentinel, lock identity, concurrent operation, unknown operation, or multiple stale operations.

### Component-relative no-follow traversal

All traversal begins from a held root descriptor and opens one component at a time with directory and no-follow flags. Revalidate the complete component chain from the held root around each operation; matching one opened directory to a stale observation is insufficient if that directory was moved outside the root.

No compound untrusted relative path, `os.walk`, glob, recursive pathname operation, `rmtree`, broad chown/chmod, or discovered-tree deletion is permitted.

### Creation and metadata order

Materialize in this exact class order:

1. directories parent-first at temporary mode 0700;
2. regular files through exclusive no-follow read/write descriptors;
3. hardlinks after their canonical regular targets settle;
4. symlinks last from literal `link_text`; and
5. directories deepest-first to final metadata, then the retained root.

For regular files, perform complete short-write-safe writes from owner-bound immutable bytes, fsync data, `fchown` before final `fchmod`, set exact mtime, fsync metadata, reread and hash the actual target, and revalidate identity and metadata before and after the reread.

For symlinks, use literal link text for creation/readback and resolved graph paths only for safety. Apply owner and mtime through exact Linux no-follow operations with parent and child identity checks before and after. Do not claim or emulate unsupported symlink chmod semantics.

Every close, fsync, metadata, readback, and reinspection uncertainty is failure. Success followed by uncertain close or durability is not success.

## Xattr and ACL policy

The source model authorizes no extended attributes or POSIX ACLs. Require an empty xattr set on the state parent, operation root, retained root, every created directory before descendants, and every final entry. This includes absence of `system.posix_acl_access` and `system.posix_acl_default`. Do not silently clear metadata or treat unavailable/unsupported inspection as empty.

Use held-fd inspection for regular files and directories. For symlinks, use exactly the held-parent `/proc/self/fd/<parent-fd>/<name>` no-follow strategy, with:

- exact held-root-to-parent chain validation;
- no-follow parent/name identity before inspection;
- strict `llistxattr` bounds and result validation;
- no-follow parent/name identity after inspection; and
- qualification against replacement, rename, procfs availability/mount behavior, hidepid settings, truncation, and unsupported-xattr results.

This is the only authorized symlink xattr/ACL strategy. If it is unavailable or cannot be proven race-safe on the approved Linux platform, stop for a new decision. Do not omit the check, invoke `getfacl`, follow the symlink, or add a fallback implementation.

## Truthful identity ledger and recovery

The ledger is write-ahead and identity-conservative. Before each named create/link operation, append and fsync a bounded canonical intent. After creation, capture the exact owned identity, append and fsync the observed record, and fsync affected parents. Final metadata receives a separate settled record.

The ledger distinguishes these states truthfully:

- **durably committed exact identity:** eligible for cleanup only after complete revalidation;
- **intent with no existing name:** safely absent after exact observation;
- **intent with an existing name but no durable observed identity:** cleanup-uncertain and preserved;
- **partial, malformed, contradictory, replaced, or unknown state:** cleanup-uncertain and preserved; and
- **settled accepted/publication state:** governed by the later R3 publication transaction.

There is no universal SIGKILL or power-loss no-residue guarantee. A crash after named creation but before durable identity commit cannot be recovered by inference. Such a name remains preserved and may block later publication until separately authorized remediation. “Anything beneath our operation directory is ours” is forbidden.

Catchable TERM/INT/HUP handlers may only latch cancellation or wake the main coordinator. They must not run filesystem or ledger cleanup reentrantly. A synchronous writer provides cooperative cancellation between bounded operations; it does not claim a hard timeout while blocked indefinitely inside a filesystem syscall without a separately reviewed guardian.

`recover-owned` accepts no path or name. While holding the fixed lock, it observes only the fixed state parent. Zero stale operations is a no-op; exactly one strict stale operation may be reconciled; multiple, malformed, unknown, or contradictory operations are uncertainty.

## Hardlink transaction model

Hardlinks are ledgered as graph-derived groups, never as unrelated names.

Each group has:

- one canonical regular target path and exact device/inode identity;
- one exact ordered alias set derived from the immutable graph;
- expected link count before and after every alias creation/removal;
- a durable transition record for every count-changing operation;
- the exact affected alias parent identity;
- linked-inode and parent fsync requirements; and
- no metadata mutation through an alias.

Before each alias, revalidate the canonical target, current expected link count, owner, type, and settled content/metadata. After link creation, revalidate shared device/inode and the next exact link count, fsync the linked inode and modified alias parent, then durably commit the group transition.

Cleanup removes aliases in the exact reverse transition order. Before and after every unlink it validates and durably records the expected link-count transition. An extra external link, unexpected ctime/link transition, replaced alias, or incomplete transaction is uncertainty and preserves the group. No relaxed “same inode somewhere” rule is permitted.

Deterministic manifests identify hardlink groups by canonical graph target, never host device/inode/ctime values.

## Complete postwalk and publication boundary

The shared no-follow walker emits two classes of information:

- logical deterministic records for rootfs equality, manifests, and pins; and
- host identity records containing device/inode/ctime/link state only for ownership, race checks, ledger, and cleanup.

The final postwalk requires the exact root identity and complete entry path set, strict byte-preserving UTF-8/NFC names, type, mode, UID/GID, mtime, archive-size semantics, regular bytes/hash, literal symlink text, canonical hardlink groups/link counts, empty xattrs/ACLs, parent graph, and device/mount policy. Unknown, missing, replaced, malformed, or extra state fails.

R3 must retire/finalize the internal operation ledger before publication through a separately reviewed transaction. Atomic accepted publication still requires one complete fsynced directory, source/destination same-device proof, exact source and destination-parent identities, `RENAME_NOREPLACE`, rename-result validation, destination-parent fsync, and recovery rules that never mistake a candidate for accepted output.

No publication behavior is authorized in R2.

## Qualification gates

### R2 synthetic Linux-root gate

R2 implementation may be developed with portable synthetic and temporary-directory tests on macOS, but it may not merge on those results alone.

Before R2 merge, obtain separate approval for one exact offline Linux-amd64/EUID-0 synthetic materializer qualification. It must prove:

- the fixed lock/state/operation/root ownership and mount policy;
- component-by-component no-follow replacement resistance;
- exact root finalization to UID/GID 0, mode 0755, and fixed mtime;
- regular, directory, hardlink, symlink, special-mode, and set-ID metadata behavior;
- chown-before-chmod ordering and actual target reread/hash;
- empty xattr/access-ACL/default-ACL state, including the held-parent procfd symlink check;
- ledger durability states and hardlink transitions;
- catchable cancellation cleanup;
- exact recoverable stale state removal;
- preservation of intent-without-identity, unknown, replaced, and contradictory state;
- complete final postwalk and no accepted output; and
- unchanged repository and cache inventory.

This gate uses synthetic fixed inputs and grants no real-cache or publication authority. It needs no external extractor, tool/helper platform pin, memfd, supervisor, pidfd, PID namespace, Docker, network, workflow, or cloud route.

### R3 real-cache gate

Only after R2 exact-head review may R3 run the real fixed cache. R3 requires two fully independent clean builds. Each independently reloads and verifies all 16 inputs, creates new immutable preflight/plan objects, uses a separate operation/root/ledger, materializes and postwalks the complete graph, and produces its own canonical manifest and ustar. Compare only settled results.

Candidate metadata remains non-authoritative and must not retain a campaign-usable root or archive. Accepted publication requires committed non-placeholder pins, a clean-head rebuild, one atomic no-replace accepted directory, exact verification, unchanged cache, and no residue or cleanup uncertainty.

Stop for exact-head hostile review before runtime closure.

## Line budget and measured stop gates

This ADR changes no numeric cap. ADR 0039's cumulative preferred target remains **8,500 lines** and its hard cap remains **9,500 lines**.

The merged R1 conservative production baseline is **5,080 lines**. Documentation and tests remain excluded from the count, but production behavior may not be moved into excluded files.

Current direct-route estimates are provisional planning envelopes, not permission to compress or pre-approve a slice:

- R2 direct materializer: **850–1,160** net lines;
- R3 deterministic outputs/pins/publication: **480–660** net lines;
- projected post-R3 cumulative total: **6,410–6,900** lines; and
- provisional whole-roadmap total: **8,910–10,650** lines.

Remeasure the affected R2 slices after the root, hardlink, ledger, symlink-xattr, and publication contracts are translated into an implementation plan. Stop and remeasure any slice that exceeds its high estimate by more than 20%, introduces a second writer/walker, requires a new native dependency/tool, or cannot preserve the fixed production boundary.

Remeasure the whole remaining campaign at exact R2 head and again at R3 exit. If the safe projected cumulative total would exceed **9,500**, implementation must stop for a cap/scope ADR before continuing. Direct-route savings are not credit for compressing filesystem ownership, Kata lifecycle, SSH/network cleanup, controller, evidence, validation, or redaction code.

## PR #204 and implementation sequence

Draft PR #204's external-extractor preparation is superseded by this accepted decision. It must be commented as superseded and closed **unmerged**. It must never be marked ready or merged as inert R2.1a.

Direct implementation starts from main containing this ADR and merged R1. Do not cherry-pick or preserve `completion_rootfs_extractor.py`, platform/tool/helper models, memfd code, supervisor/PID-namespace work, or external-route behavior for sunk-cost reasons.

Implement only one direct route in narrow reviewed slices. Open a new draft security PR after the first authorized slice and hostile local review. Never maintain direct and external composition routes in parallel.

## Boundaries retained from ADR 0038 and ADR 0039

All unmodified requirements remain binding, including:

- the exact Debian OCI base, snapshot, ten packages, versions, sizes, hashes, architecture, and package order;
- no maintainer-script execution, package-manager installation during composition, eleventh package, silent dependency expansion, or rootfs/package/input drift;
- exact generated account/configuration semantics and no generated static key material;
- two independent identical rootfs builds and committed pins before cloud consideration;
- later dynamic-link, version, `sshd -t`, strict authenticated SSH, and fixed Git qualification, with stop/replan on insufficiency;
- the separate deterministic representative Git and package build/local `dpkg` install workloads;
- exact Kata `/30` namespace/veth/tcfilter/no-default-route/no-host-network semantics;
- seven sequential fresh cycles, one full and six readiness, no overlap or stop/start substitution;
- immediate state-bound destroy, per-cycle and final independent zero inventory, no forced cleanup, and no evidence after uncertainty;
- the existing region, instance type, resources, disk, expiry, deadline, cost, approval phrase, and separate exact future cloud approval;
- strict completion evidence, recomputation, redaction, no partial publication, and no accepted historical evidence changes; and
- ADR 0039's counted file set, implementation discipline, preferred target, and hard cap.

The later representative package workload remains exactly the fixed deterministic `dpkg-deb --build` plus local `dpkg` install described by ADR 0038. Removing `dpkg-deb -x` from rootfs composition does not remove or authorize changes to that workload.

## Stop gates and non-claims

Stop for another ADR or explicit owner decision before:

- changing the root policy, immutable input set, ten-package order, transition graph, metadata semantics, writer/walker count, ledger uncertainty semantics, hardlink transaction model, or symlink xattr strategy;
- adding an external/staged extractor, fallback route, arbitrary archive/package/root/path/command/configuration API, package-database fiction, general OCI/package tooling, host tar, or maintainer-script execution;
- treating unavailable xattr/ACL/procfd/no-follow behavior as success;
- deleting intent-without-durable-identity, unknown, replaced, contradictory, or extra state by inference;
- claiming universal SIGKILL/power-loss recovery or a hard filesystem-syscall timeout;
- adding a dependency, workflow change, Docker route, network acquisition, cloud execution, provider action, deployment, release, or production scope;
- changing ADR 0038's package, network, SSH, cleanup, evidence, cost, time, resource, or cloud boundaries; or
- exceeding ADR 0039's 9,500-line hard cap.

This ADR provides no materialized rootfs, pin, qualification evidence, runtime-closure claim, SSH-ready result, Git result, cloud plan/apply/inventory authority, AWS execution approval, workflow approval, release claim, production-readiness claim, or issue closure.

## Consequences

Issue #42 rootfs composition can proceed with one reviewable semantic authority and one filesystem writer instead of a second archive interpreter plus a root process lifecycle. The incremental TCB is the accepted Python/preflight model, direct writer/walker, ownership ledger, Linux filesystem, and metadata syscalls. It is smaller, not absent.

The principal risk is concentrated in root fd-relative filesystem and cleanup code. Future implementation must keep that code readable, hostile-tested, identity-conservative, and bounded by the Linux-root gate. Any uncertainty preserves state and stops publication.

All cloud and runtime evidence remains where ADR 0038 placed it: closed until every local qualification gate passes and Nick Byrne separately approves one exact named batch.
