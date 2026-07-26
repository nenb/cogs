# ADR 0066: Authorize one Phase B discovery lifecycle

- Status: Proposed
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Amendment scope: One candidate-only lifecycle for ADR 0065 Phase B discovery. Every non-conflicting ADR 0038–0065 requirement remains binding.

## Context

ADR 0065 requires its single non-authoritative `phase-b-discovery` event to collect actual normalized command-output, stored-spec, process, share, and SSH facts. It also says that no rootfs, fixture, package, or guest-closure discovery is authorized.

The pre-event hostile review recorded P1-03: the proposed collector did not start private containerd or create a Kata task. Instead, it digested test-only `UNQUALIFIED_*` snapshots and constants. That cannot establish the required environmental facts. An actual Kata task and its QMP, process, share, and authenticated-SSH behavior cannot exist without a guest rootfs, fixed guest inputs, and the fixed network lifecycle. Invoking binaries with `--version`, launching an unrelated QEMU probe, or hashing offline parser fixtures cannot substitute for that lifecycle.

This is a mechanism blocker, not evidence that any accepted rootfs or fixture pin is wrong. Phase A run `30218838605` already qualified the exact 16-artifact rootfs route, two-build equality, committed manifest and ustar pins, cleanup, and final observation at exact head `de027e33312be49e5b825c0abc7e864688ae2aaa`. Existing Stage 2 modules already define the retained rootfs lease and the fixed operation, input, network, runtime, SSH, process, and coordinator ownership domains. Discovery needs a narrowly non-authoritative way to reproduce and use those prerequisites; it does not need another rootfs fact, rootfs writer or extractor, fixture, or production permit.

No `phase-b-discovery` event was created or consumed by the rejected pre-event implementation or its review. ADR 0065's first-created-event rule remains the only event authority.

## Decision

If accepted, authorize exactly one fixed, no-argument, non-authoritative discovery lifecycle within ADR 0065 Phase B slice 1. It may reproduce and use the already-pinned rootfs and fixtures solely as prerequisites for collecting the actual facts ADR 0065 already requires.

### Exact lifecycle

The discovery route must perform this sequence once, without a scenario selector:

1. Bind the exact event head, reviewed head, fixed source, 16 rootfs artifacts, committed rootfs manifest/ustar pins, runtime-asset pins, host-tool candidates, and pre-mutation baselines under all retained ADR 0065 workflow and source checks.
2. Through the unchanged qualified rootfs build and `completion_rootfs_lease.py` acquisition route, perform exactly one lease acquisition. Preserve its two independent fresh materializations, equality and pin checks, and retain only its second exact lease. Do not add or substitute a rootfs writer, walker, extractor, cache, acquisition route, publication route, or lease protocol.
3. Open only sealed candidate-discovery grants over the existing operation, input, network, process, runtime, SSH, and coordinator owners. Materialize only the already-pinned fixed inputs, establish only the accepted fixed `/30` network, and start only private containerd with Kata. Create one minimal fixed container and task using the retained rootfs lease and existing fixtures. Private containerd must be represented by the fixed durable daemon transition defined below before it can execute.
4. From that actual task lifecycle, collect and normalize the already-authorized command outputs and private-containerd stored OCI spec; query the actual Kata VM's QMP endpoint and require KVM present and enabled; observe the actual container/task, shim, QEMU, virtiofsd, mount, and share state; and perform the fixed strict authenticated-SSH readiness exchange over the fixed network. Test snapshots, parser fixtures, constants, `UNQUALIFIED_*` values, a standalone QEMU process, and version-only invocations cannot supply or replace any candidate fact.
5. Revoke SSH readiness and execute the complete accepted teardown through the existing owners and operation journal. Require task, network, container, runtime, share, firewall, input, and private-containerd teardown in the accepted order, authorize and complete rootfs release through the existing lease owner, retire the operation, and independently prove all inherited baselines and zero residue.
6. Only after successful teardown, rootfs release, owner closure, and independent zero-residue proof may the runner finalize, write, validate, export, or upload bounded candidate metadata. Before that boundary, observations may exist only as bounded in-memory lifecycle state. A failure or cleanup uncertainty may produce the inherited categorical workflow failure record, but no discovery candidate metadata.

Any lifecycle failure consumes the event, enters the same accepted teardown without retry, and grants nothing. Inability to complete exact teardown, release the rootfs, close owned processes and descriptors, or prove zero residue is a mandatory stop.

### Candidate-only grants and non-authority

Candidate-discovery grants must be closure-sealed, fixed-purpose, and obtainable only inside the exact no-argument discovery route after its prerequisite checks. They may issue only the fixed commands and lifecycle transitions above. They cannot be caller-constructed, serialized, selected by input or environment, converted into an accepted owner type, passed to the committed qualification gate, or reused after teardown.

The existing committed gate remains fail-closed and independent. Discovery cannot claim or modify it, open a production permit, promote candidate values, or make a production owner available. The later manually committed attestation and authoritative Phase B route must still independently reproduce every committed fact before production-owner mutation as required by ADR 0065.

The private-containerd prerequisite may add only a fixed daemon-intent/started/stopped action vocabulary and its exact operation-journal transitions in `completion_kata_actions.py` and `completion_kata_operation.py`, plus the corresponding fixed process/runtime implementation. Before fork, the journal must durably record intent. The child must remain blocked on a parent-owned gate until the parent has durably recorded its exact PID, starttime, executable inode identity, operation identity, and expected fixed argv/config digests. Parent death before that record must close the gate and make the child exit without exec. Recovery or teardown may signal only after revalidating every recorded identity; it must TERM, bounded-KILL if needed, reap when still a child, and prove absence. Unknown, changed, malformed, or only partly recorded identity forbids broad cleanup and leaves the result uncertain. No caller-selected daemon, command, path, action, signal, or recovery route is authorized.

This lifecycle is not ADR 0065's authoritative normal/startup-failure/timeout/interrupt/durable-recovery scenario matrix. It runs no injected failure scenario, full scenario, Git or package workload, seven-sample workload, campaign, evidence/readiness route, production use, or step 3 or later behavior. Its sole purpose is to obtain reviewable candidate attestations from one authentic minimal Kata lifecycle and then leave zero residue.

### Rootfs and fixture boundary

This ADR supersedes only ADR 0065's sentence, “No rootfs, fixture, package, or guest-closure discovery is authorized,” and only as follows:

> No new rootfs, fixture, package, or guest-closure fact, pin, content, or discovery is authorized. The one candidate lifecycle may reproduce and use the already-pinned rootfs and fixtures, including their already-pinned guest closure, only as lifecycle prerequisites. Their identities may be recorded only as equality bindings to existing pins; no observed value may become a new rootfs, fixture, package, or guest-closure candidate.

Actual task, stored-spec, QMP, process, share, network, and SSH observations remain runtime-attestation candidates, not new fixture or guest-closure facts. An apparent rootfs/fixture mismatch, missing prerequisite, or need for a new pin is a stop and replan.

## Implementation scope

The added lifecycle behavior may use only these existing implementation owners and their existing tests:

- `deploy/aws-feasibility/remote/completion_rootfs_lease.py`, unchanged and only through its fixed two-build lease/release route;
- `completion_kata_actions.py`;
- `completion_kata_operation.py`;
- `completion_kata_inputs.py`;
- `completion_kata_network.py`;
- `completion_kata_runtime.py`;
- `completion_kata_ssh.py`;
- `completion_kata_coordinator.py`;
- `completion_kata_qualification.py`;
- `completion_kata_process.py`;
- `scripts/run-stage2-phase-a-candidate.py`; and
- the already-existing Kata and Phase A runner test companions.

Paths without a directory above are under `deploy/aws-feasibility/remote/`. For this lifecycle only, this is the complete narrow correction to ADR 0065 slice 1's implementation list; candidate-discovery use of these owners is not Phase B slice 2 authority and does not advance the slice order. It supersedes only the quoted no-discovery sentence and, solely for the fixed private-daemon mechanism above, ADR 0065's exclusion of `completion_kata_actions.py`, prohibition on a journal-protocol addition, and Phase B total/action-file high.

Add no production or test module. Except for the fixed private-daemon actions and transitions above, `completion_kata_fdmap.py`, rootfs build/materializer/canonical/publication modules, fixture modules, package/lock files, and unrelated code remain unchanged. `completion_rootfs_lease.py` receives no new per-file allowance; needing to change it is a stop and replan. ADR 0065's already-authorized fixed data-only attestation contract, Phase B schema, and existing workflow wiring receive no additional behavior or allowance from this ADR.

Reuse owners rather than copy them. Add no mount, package, fixture, rootfs or runtime pin, caller-selected command surface, generic path/config API, rootfs writer or extractor, module, fallback, retry, recovery attempt, event, timeout, or deadline. The fixed private-daemon identity is part of the existing operation owner, not a second lifecycle owner or generic process manager. Runtime-asset materialization remains confined to ADR 0065's already-authorized fixed runtime-owner route; do not add a second extraction path or module. The lifecycle uses only the mounts already required by the accepted rootfs, input, private-containerd/Kata, and fixed-network design.

The collector must retain ADR 0065's metadata limits. It may emit only schema-validated normalized values, digests, exact existing-pin bindings, and categorical outcomes. It must not upload raw output, commands, paths, addresses, process rows, mount rows, share names, stored specs, SSH material, logs, runtime/rootfs bytes, or ownership state.

## Unchanged event, counts, and gates

This ADR creates no additional or replacement event. The same singular `.github/workflows/stage2-phase-a-candidate.yml` workflow, exact `phase-b-discovery` marker, same-repository labeled trigger, earliest-run guard, attempt 1, exact reviewed-head binding, 90-minute outer timeout, internal non-borrowing deadlines, and first-created-run consumption rule from ADR 0065 remain binding. If that event authority is consumed before this correction's reviewed implementation runs, this ADR grants no hosted run. A new head does not renew it.

There is no line-budget reset. The proved missing fixed-daemon action/state needs one narrow allowance; every other Phase B high remains unchanged:

| Counted file/surface | Gross high |
| --- | ---: |
| `scripts/run-stage2-phase-a-candidate.py` | 220 |
| `completion_kata_qualification.py` | 320 |
| Phase B schema | 220 |
| `completion_kata_actions.py` | 40 |
| `completion_kata_operation.py` | 360 |
| `completion_kata_process.py` | 430 |
| `completion_kata_inputs.py` | 260 |
| `completion_kata_network.py` | 280 |
| `completion_kata_runtime.py` | 520 |
| `completion_kata_ssh.py` | 90 |
| `completion_kata_coordinator.py` | 500 |
| `run-stage2-completion-remote.sh` | 20 |
| **Measured plan total** | **3,260** |
| Review contingency | **50** |
| **Absolute Phase B high** | **3,310** |

Unused allowance cannot fund another file, and deletion or replacement of rejected code creates no credit. The conservative issue projection rises from 33,304 to 33,344, still strictly below the 34,000 hard cap; the preferred 32,000 target is exceeded and remains documented. The strict-less-than formula, steps 3–4 highs, and future-work accounting remain unchanged.

Before any event, run every ADR 0065 check applicable to the changed files and lifecycle. Existing tests must prove one unchanged two-build lease acquisition, actual-owner collection rather than fixture substitution, grant separation, the pre-exec daemon gate and every intent/identity/reap failure cut, private-containerd/Kata task and QMP correlation, actual stored-spec/process/share/SSH normalization, fail-closed teardown at every implemented cut, rootfs release, report-after-residue ordering, and final zero residue without adding fixtures. Require one independent exact-range review with no unresolved P0–P3 finding.

This ADR resolves only the prerequisite-authority and fixed-daemon mechanism conflicts exposed while correcting P1-03. It does not waive or disposition P1-01, P1-02, P1-04 through P1-08, or P2-01 through P2-03 from the same hostile review. Every applicable finding must be corrected under existing ADR 0065 scope and caps and receive clean rereview before the sole event.

## Consequences

Discovery can now observe the environmental facts that exist only during a real Kata lifecycle while preserving the distinction between prerequisite reproduction and discovery of new rootfs or fixture facts. Candidate output still has no authority, and complete teardown precedes its existence as durable metadata.

Every non-conflicting ADR 0065 production, authoritative-Phase-B, workload, step-5, campaign, release, issue-closure, cloud, and AWS stop remains binding. This proposed documentation-only ADR creates no implementation, commit, label, event, run, acquisition, materialization, KVM access, lifecycle, metadata, production, cloud, or AWS authority until accepted.
