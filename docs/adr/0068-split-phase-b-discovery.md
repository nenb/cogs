# ADR 0068: Split Phase B discovery into runtime and lifecycle slices

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Amendment scope: Supersede ADR 0066 only where it combines runtime-asset discovery and authentic lifecycle discovery into one `phase-b-discovery` lifecycle/event. Amend ADR 0065's Phase B ordering and hosted-gate count and ADR 0067's retained singular-stage/event-count clauses accordingly. Every other non-conflicting ADR 0065–0067 requirement remains binding.

## Context

ADR 0066 requires the only Phase B discovery implementation to commit an exact archive/member/postwalk and extraction-helper contract before the exact pinned Kata runtime archives have been inspected, while also using that contract to run the authentic private-containerd/Kata lifecycle that discovers process, QMP, share, stored-spec, network, and SSH facts. That is circular. Unknown archive types or layouts must be rejected rather than adopted, but the required fixed policy and complete hidden-helper closure cannot be reviewed authentically until the pinned archives are available.

The rejected one-event implementation demonstrated the problem. Its archive and extracted-postwalk policies disagreed; its tar decompressor child was not completely owned; process correlation and QMP access were assumptions rather than authenticated observations; its residue route was deterministically broken; and recovery remained incomplete. Using the sole discovery event to test these guesses would consume the gate on an expected failure and still require a correction ADR.

The rejected implementation was reverted at `bfacac2f44b6560b2f7c648ef7ce5e9433bef25e`. It must not be restored or patched as the qualification design. Phase B instead needs one bounded runtime-asset event whose manually reviewed facts make the authentic lifecycle reviewable, followed by a separate non-authoritative lifecycle event whose manually reviewed facts make the authoritative scenario matrix reviewable.

## Decision

Phase B is exactly three ordered slices. A later slice receives no authority until the preceding event has stopped, its bounded candidate has been manually reviewed and committed where applicable, the new exact head has passed all applicable local checks and an independent exact-range hostile review with no unresolved P0–P3 finding, and every per-file and aggregate cap remains satisfied.

### Slice 1: `phase-b-runtime-discovery`

Permit at most one attempt-1 event at one clean exact reviewed head. It may:

1. acquire exactly the two already-pinned runtime archives once through the existing acquisition/runtime route;
2. verify each fixed byte size and SHA-256 value before use;
3. enumerate the complete archive member, type, mode, and size layout under fixed type, count, per-member-size, aggregate-size, path-length, and output bounds;
4. reject absolute member names, traversal, duplicate or ambiguous names, devices, FIFOs, sockets, malformed headers, and any unrecognized or out-of-bounds layout; classify regular files, directories, symlinks, and hard links without extracting them; normalize every link target and record only bounded target-class counts and digests; and
5. produce a canonical complete-member-manifest digest and bounded aggregate type/count/size/link-target-class facts; and
6. identify the complete actually required extraction executable, loader, library, decompressor, and child-helper closure, with every process and descendant durably owned and revalidated.

This event must not access KVM; acquire, build, materialize, or lease a rootfs; publish an extraction to `/opt/kata` or any other host lifecycle location; start private containerd, Kata, a VM, container, or task; establish the fixed guest network; query QMP; use SSH; or collect any lifecycle fact. It grants no extraction publication, lifecycle, production, workload, or authoritative authority.

Every downloader, parser, archive helper, decompressor, child, descriptor, partial, cache object, and private temporary layout must have durable ownership before an unrecoverable cut. Recovery must reject intent-only or foreign state, narrowly revalidate identities before signaling or deletion, and independently prove process, descriptor, cache, partial, and temporary-layout absence before candidate metadata can exist. Failure or uncertainty enters bounded cleanup, emits no candidate, consumes the event, and grants nothing.

After the event, always stop. The bounded report may be structurally valid with `qualified:false` and categorical blockers after complete cleanup—for example an unsafe absolute link target or unsupported member type—because discovery must preserve rather than hide the fact it was created to learn. Such a blocker grants no later-slice authority. A size, hash, layout, member-type, link-target, helper-closure, executable, loader, library, cleanup, or metadata mismatch requires a new mechanism decision; it cannot be inferred or adopted.

On a later clean head, a human may manually review and initially create `deploy/aws-feasibility/remote/stage2-completion-runtime-attestation-v1.json` as the one already-authorized fixed data-only Phase B attestation contract, containing only the bounded runtime pin. No code or workflow may copy, select, synthesize, transform, or promote candidate values. The only newly permitted public values are bounded archive-relative member names for the fixed required runtime roles in this asset candidate and its manually committed pin. They must be normalized members of the verified archive manifest and must not be host paths, commands, argv, process rows, logs, addresses, archive bytes, ownership state, selectors, or executable data. The complete canonical member manifest and normalized link targets are represented publicly only by digests and bounded aggregate facts.

### Slice 2: `phase-b-lifecycle-discovery`

After the runtime-asset pin and mandatory stop, permit at most one attempt-1 event on a new clean exact reviewed head. Before any mutation, it must independently acquire exactly the two pinned archives once through the fixed route and reproduce the committed archive identities, canonical layout digest, bounded aggregate facts, fixed role members, and complete extraction executable/loader/library/helper closure. A mismatch stops before rootfs, KVM, owner opening, extraction publication, or lifecycle mutation.

The slice then runs exactly one fixed no-argument, non-authoritative ADR 0066 lifecycle candidate. It may reproduce and use only the already-pinned rootfs and fixtures through the unchanged two-build retained lease route; publish the verified fixed runtime through the existing runtime owner; open only the existing sealed operation, input, network, process, runtime, SSH, and coordinator ownership domains; and run one minimal private-containerd/Kata container and task. From that authentic lifecycle it collects the actual extracted postwalk, private-containerd stored OCI spec/information, container and task, shim/QEMU/virtiofsd, mount/share, QMP KVM-present/enabled, fixed-network, and strict authenticated-SSH candidate facts already required by ADRs 0065–0066.

Observed argv, process, cgroup, socket, QMP, share, stored-spec, network, or SSH values are candidate observations only. They cannot authorize ownership adoption, signaling, deletion, unmounting, teardown, or publication. Those actions must derive from the sealed launch, durable operation/container/task identities, causally captured child identities, committed runtime pin, and pre-mutation baselines. Stop before the event if safe cleanup depends on a value being discovered, an argv substring, an inferred socket, pathname-only observation, intent-only state, foreign state, or broad signaling/deletion.

The lifecycle must execute the complete accepted teardown, rootfs release, owner and descriptor closure, restored-baseline checks, and independent categorical zero-residue proof before candidate metadata can exist. Any lifecycle failure or uncertainty enters that same teardown without retry. This event is not the authoritative normal/startup-failure/timeout/interrupt/durable-recovery matrix and grants no production or workload authority.

After the event, always stop. On a later clean head, a human may manually review and add the bounded lifecycle pin to that same `stage2-completion-runtime-attestation-v1.json` fixed data-only Phase B contract. No code or workflow may copy, select, synthesize, or promote it. A parser, configuration, process, QMP, SSH, teardown, recovery, residue, or candidate mismatch consumes this gate and requires a new accepted mechanism or correction ADR as applicable.

### Slice 3: `phase-b-authoritative`

Retain ADR 0065's authoritative Phase B slice on a third new clean exact reviewed head. Before mutation, independently reproduce every committed source, host-tool, runtime archive/layout/helper/postwalk, network, SSH, KVM, stored-spec, process, share, rootfs, and fixture fact. Then execute the production normal, startup-failure, timeout, interrupt, and later-process durable-recovery paths and require complete owner closure, restored baselines, and independent zero residue.

Success grants only authoritative local standalone-Kata Phase B at that exact revision. It grants no workload, step-3, campaign, production, release, issue-closure, cloud, or AWS authority.

## Manual boundaries and slice order

The order is mandatory:

1. review and run `phase-b-runtime-discovery`; stop;
2. manually review and commit only its bounded runtime pin; perform a new exact-head review;
3. review and run `phase-b-lifecycle-discovery`; stop;
4. manually review and commit only its bounded lifecycle pin; perform a new exact-head review; and
5. review and run `phase-b-authoritative`.

No success, spare time, favorable observation, or new commit skips a stop or transfers authority forward. No result is automatically promoted. Candidate and committed routes remain distinct, private, closure-sealed, fixed-purpose, and zero-argument.

## Workflow and event authority

The hosted stage-marker set is exactly:

- `phase-b-runtime-discovery`;
- `phase-b-lifecycle-discovery`;
- `phase-b-authoritative`;
- `workload-candidate`;
- `workload-post-pin`; and
- `workload-full`.

This replaces every ADR 0065–0067 reference to five hosted gates, an unchanged event count, or the singular/sole `phase-b-discovery` gate with six hosted gates and the two named non-authoritative discovery gates. ADR 0067's caps, finding-closure requirements, accounting, and every unrelated boundary remain unchanged. The three workload markers and their conditional authority are unchanged.

Reuse only `.github/workflows/stage2-phase-a-candidate.yml` with ADR 0065's same-repository `pull_request` `labeled` trigger, exact `security` label equality, permissions, token isolation, fixed actions, runner, source/reviewed-head bindings, and literal stage binding. Do not create, repurpose, or use another workflow.

Each of the six named gates has independent authority for at most one first-created run. Each run must be attempt 1, the earliest exact-head/exact-marker run proved by the existing exhaustive guard, and bound to one clean exact reviewed full head. Creation consumes that named gate regardless of success, failure, cancellation, skip, timeout, duplicate detection, or uncertainty. There is no rerun, retry, fallback, favorable-run selection, relabel, replacement sample, or timeout increase. Retain the existing 90-minute outer timeout, all internal deadlines, and the non-borrowing cleanup/reporting reserve. A new head does not renew a consumed gate. A corrective event still requires the narrow separately reviewed and accepted proved-defect correction ADR specified by ADR 0065.

## Existing implementation boundary

Reuse the existing Phase A runner, the one existing workflow, the ADR 0066 implementation owners, and their existing tests. Authorize initial creation of exactly one schema, `schemas/stage2-phase-b-qualification-v1.json`, before runtime discovery, and exactly one fixed data-only contract, `deploy/aws-feasibility/remote/stage2-completion-runtime-attestation-v1.json`, only at the first manual pin after successful runtime discovery. The second manual pin may update that same contract and nothing else may create or modify it. No other production or test module, workflow, schema, contract, owner, writer, walker, journal protocol, selector, generic command/path/config API, retry, fallback, timeout, deadline, cleanup mechanism, rootfs route, extraction route, or publication route may be added.

The complete permitted implementation-file set remains:

- `scripts/run-stage2-phase-a-candidate.py`;
- `schemas/stage2-phase-b-qualification-v1.json` and, only after runtime discovery, `deploy/aws-feasibility/remote/stage2-completion-runtime-attestation-v1.json`;
- `.github/workflows/stage2-phase-a-candidate.yml`;
- `deploy/aws-feasibility/remote/completion_kata_actions.py`;
- `deploy/aws-feasibility/remote/completion_kata_operation.py`;
- `deploy/aws-feasibility/remote/completion_kata_inputs.py`;
- `deploy/aws-feasibility/remote/completion_kata_network.py`;
- `deploy/aws-feasibility/remote/completion_kata_runtime.py`;
- `deploy/aws-feasibility/remote/completion_kata_ssh.py`;
- `deploy/aws-feasibility/remote/completion_kata_coordinator.py`;
- `deploy/aws-feasibility/remote/completion_kata_qualification.py`;
- `deploy/aws-feasibility/remote/completion_kata_process.py`;
- `deploy/aws-feasibility/remote/run-stage2-completion-remote.sh`; and
- the already-existing Kata and Phase A runner test companions.

`completion_rootfs_lease.py` remains unchanged and is callable only by the lifecycle and authoritative slices through its fixed two-build lease/release route. `completion_kata_fdmap.py`, rootfs build/materialization/publication code, fixture code, package code, lock files, and unrelated code remain unchanged. Needing another file or mechanism is a stop and replan.

## Required final-review finding closure

The rejected implementation and its revert do not disposition any final-review finding. The exact full finding texts P1-A through P1-I, P2-A, and P3-A remain binding; the summaries below preserve rather than replace them.

Before `phase-b-lifecycle-discovery`, and again where applicable before `phase-b-authoritative`, the implementation must satisfy all of them:

- **P1-A — rootfs acquisition ownership:** one exact acquisition, durable ownership before every unrecoverable cut, no duplicate acquisition, and cleanup/recovery at every acquisition cut.
- **P1-B — later-process recovery and signaling:** mandatory later-process recovery without replaying the one-shot lifecycle; exact identity revalidation; sound parent-death/reparenting handling; and no group-wide action from leader identity alone.
- **P1-C — truthful journal transitions:** no uncertainty-to-absence conversion, synthesized proof, or rootfs release without actual durable teardown evidence.
- **P1-D — closure-only grants:** grants exist only inside the fixed no-argument coordinator closure, with no caller factory or selected command/spec surface.
- **P1-E — runtime/private-layout recovery:** recover rename-before-publication cuts, reject intent-only or foreign adoption, and prove durable narrow ownership before destructive action.
- **P1-F — complete independent residue proof:** correctly handle empty Linux `/proc/<pid>/cmdline` and independently observe every process, nft, tc, operation-directory, share, mount, runtime, cache, rootfs, and retained-identity residue class.
- **P1-G — exception-safe descriptor closure:** track and close every descriptor exception-safely, aggregate close failures, and never advance while closure is uncertain.
- **P1-H — archive and helper contract consistency:** one bounded policy must agree across archive enumeration, extraction, and extracted postwalk; every tar/decompressor/loader/library/helper descendant must be owned; unknown layout or type must be rejected rather than adopted.
- **P1-I — authentic lifecycle correlation and recovery:** derive task/container/shim/QEMU/virtiofsd/QMP/share/SSH correlation and teardown authority from durable causal identities and baselines, not assumed argv or sockets; the residue route and mandatory later-process recovery must be reachable and correct.
- **P2-A — authentic integrated coverage:** exercise the actual candidate owner graph and production parsers, including retained-root container information, authentic archive supervision, timeout-to-later-process recovery, broad-signal/delete rejection, every rootfs/layout/publication cut, descriptor faults, nft and complete residue observation, QMP access/correlation, strict SSH, and the report-after-zero-residue boundary. Synthetic tests supplement but never replace authentic evidence.
- **P3-A — readable security code:** express ownership, proof, mutation, recovery, and cleanup in ordinary readable transitions; cap-driven chaining or proof compression is forbidden.

The runtime-asset slice has the narrower applicable boundary: exact one-time two-archive acquisition; durable downloader/parser/helper/descendant ownership; complete bounded manifest and helper closure; truthful partial/cache/publication state; exception-safe descriptors; narrow recovery and signaling; independent cache/process/temporary-layout residue proof; report-after-residue ordering; authentic archive supervision tests; and readable code. It neither implements nor synthetically claims rootfs, KVM, QMP, network, SSH, private-containerd, Kata, or lifecycle closure. The lifecycle slice must satisfy every P1-A–P1-I/P2-A/P3-A requirement in full.

## Counts

ADR 0067's exact baseline, non-transferable per-file maxima, and aggregate remain unchanged:

| Counted file/surface | Gross high |
| --- | ---: |
| `scripts/run-stage2-phase-a-candidate.py` | 240 |
| `completion_kata_qualification.py` | 320 |
| Phase B schema | 220 |
| `completion_kata_actions.py` | 40 |
| `completion_kata_operation.py` | 400 |
| `completion_kata_process.py` | 600 |
| `completion_kata_inputs.py` | 260 |
| `completion_kata_network.py` | 280 |
| `completion_kata_runtime.py` | 800 |
| `completion_kata_ssh.py` | 90 |
| `completion_kata_coordinator.py` | 500 |
| `run-stage2-completion-remote.sh` | 20 |
| **Absolute Phase B high** | **3,310** |

Gross additions remain measured against exact baseline `84b30d30b3307f1c5222dd9e50dfa755cdee673a`. Per-file room is non-transferable; the 3,310 aggregate is binding; deletion, revert, replacement, rename, moved logic, generated code, tests, workflows, excluded surfaces, or compression creates no credit. Do not restore `8c646c0` and claim its deletion as budget.

The conservative projection remains:

`26,074 no-deletion reserve + 3,310 Phase B + 1,900 steps 3–4 + 2,060 future = 33,344 < 34,000`.

The 656-line hard-cap headroom grants no implementation allowance. The 32,000 preferred target remains exceeded and documented; the 34,000 hard cap is unchanged.

## Checks and review gates

Before each exact-head event, run every ADR 0065–0067 check applicable to that slice. At minimum run:

```sh
npm run format:check
npm run typecheck
npm run schemas
npx tsx --test test/aws-stage2-completion-kata-*.test.ts
python3 -I test/aws-stage2-completion-kata-network.py
python3 -I test/aws-stage2-completion-kata-runtime.py
python3 -I test/aws-stage2-completion-kata-s5.py
git diff --check
npm run check
```

On native Linux amd64, run the existing process, root-owned operation, guarded real-input, owner-graph, recovery-cut, descriptor-fault, residue, and authentic archive/lifecycle tests applicable to the slice. Local generated archives and benign processes must cover strict metadata, acquisition/cache crash cuts, hostile layouts, canonical-manifest stability, complete descendant supervision, malformed output, closure-only grants, owner state cuts, report-after-residue ordering, and categorical zero residue. They are non-authoritative and cannot establish actual pinned layout/helper, postwalk, Kata/QMP/process/share, or strict SSH facts.

Record the clean predecessor, exact 40-hex head, physical lines, per-file gross additions, complete 3,310 aggregate, and all applicable test results before and after each slice. Obtain an independent hostile review of each exact baseline-to-head range with no unresolved P0–P3 finding. Any change after review invalidates that review.

## Mandatory stops and consequences

At every event, stop for attempt above 1; a non-earliest or duplicate run; dirty, mismatched, or unreviewed head; raw or forbidden metadata; automatic promotion; cap breach; unknown-to-absent conversion; unowned process, descriptor, cache, partial, extraction, mount, or runtime state; broad signaling/deletion; retry; fallback; timeout increase; uncertain cleanup; residue; report-before-residue; or any later-slice action after failure.

Stop before step 5 and before every AWS credential, `AWS_*` authority, CLI/account lookup, provider, Terraform/OpenTofu, plan, inventory, apply, SSM, deployment, resource, campaign, cloud cleanup, or other cloud action. This ADR grants no AWS authority.

This proposed documentation-only ADR creates no implementation, commit, label, ready transition, event, run, acquisition, rootfs, extraction publication, KVM access, lifecycle, metadata, production, workload, deployment, cloud, or AWS authority until accepted.
