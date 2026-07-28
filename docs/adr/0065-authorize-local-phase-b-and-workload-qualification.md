# ADR 0065: Authorize local Phase B and workload qualification

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing authorization to complete all non-AWS work, after independent hostile review and focused rereview reported no unresolved P0–P3 findings.
- Acceptance record: [GitHub pull request #236](https://github.com/nenb/cogs/pull/236).
- Decision scope: One consolidated local-only decision for Phase B and, conditionally, steps 3–4. All non-conflicting ADR 0038–0064 requirements remain binding.

## Context

GitHub Actions run [`30218838605`](https://github.com/nenb/cogs/actions/runs/30218838605), attempt 1, succeeded at exact reviewed head `de027e33312be49e5b825c0abc7e864688ae2aaa` (`de027e3`). It authenticated the fixed-source manifest `4762a3a3bd9c9e0c1e4b2c603e9a6ef435909519e23d42a81b37b37b1a7a9936`, acquired the exact 16 rootfs artifacts, completed two fresh 4,353-entry builds equal to the committed manifest and ustar pins, and passed exact cleanup and final observation.

That run is authoritative only for its rootfs scope. It acquired no runtime assets and made no KVM/QMP, Kata, network, SSH, coordinator, Phase B, workload, campaign, production, or AWS claim. Phase B remains fail-closed because committed host/runtime attestations and production owner wiring do not exist.

At `de027e3`, the ADR 0039 anti-evasion counted surface is:

| Counted basis | Physical lines |
| --- | ---: |
| `deploy/aws-feasibility/**/*.{sh,py,tf}` | 18,403 |
| Frozen ADR 0039 historical schema/validator/renderer set | 591 |
| `scripts/prepare-stage2-fixed-source.py` | 1,049 |
| `scripts/run-stage2-phase-a-candidate.py` | 2,490 |
| `scripts/stage2-phase-a-budget.py` | 75 |
| `schemas/stage2-phase-a-candidate-v1.json` | 268 |
| `schemas/stage2-phase-a-candidate-v2.json` | 1,955 |
| **Actual retained count** | **24,831** |

ADR 0057's 25,634-line no-deletion reserve plus 440 gross rootfs production additions gives the current conservative **26,074-line no-deletion reserve**. The retained roadmap highs are:

| Remaining scope | High |
| --- | ---: |
| Phase B | 3,270 |
| Steps 3–4 | 1,900 |
| Future steps 5–7 | 2,060 |
| **Total** | **7,230** |

The conservative projection is `26,074 + 3,270 + 1,900 + 2,060 = 33,304`, which is **696 lines below** 34,000. The actual-count projection is 32,061. The accepted **32,000 preferred target** and **34,000 hard cap** remain unchanged. The preferred target creates no pressure to compress security or cleanup code.

## Decision

If accepted, authorize only the ordered local qualification below. Phase B has at most three slices. Steps 3–4 have at most three further slices and are conditional on authoritative Phase B success and a fresh cap gate. A later slice receives no authority until the preceding slice's required local/KVM event succeeds at its exact reviewed head. The five hosted gates are exactly `phase-b-discovery`, `phase-b-authoritative`, `workload-candidate`, `workload-post-pin`, and `workload-full`; the event-consumption rules below apply equally to the non-authoritative discovery gate and the four authority-bearing gates.

### Phase B slice 1: one non-authoritative attestation discovery

Start only from exact base `de027e33312be49e5b825c0abc7e864688ae2aaa`. Reuse the existing Phase A runner and the Phase A candidate workflow at `.github/workflows/stage2-phase-a-candidate.yml`. Extend only `completion_kata_qualification.py`, `completion_kata_process.py`, `completion_kata_runtime.py`, `scripts/run-stage2-phase-a-candidate.py`, the fixed data-only attestation contract, the Phase B schema, and that existing workflow's wiring.

Authorize at most **one** metadata-only, non-authoritative host/runtime attestation discovery run. It may collect only the plan's exact source/runner facts; complete `ctr`, `ip`, `tc`, `nft`, `ssh`, `ssh-keygen`, and actually required extraction-helper executable/loader/library identities; strict runtime archive layout and extracted postwalk; `/opt/kata` and private containerd identities; KVM API 12 and QMP KVM-present/enabled facts; and normalized command-output, stored-spec, process, and share fixture digests.

The candidate cannot claim the committed gate, open a production owner, or become authority. Stop after its outcome. Candidate values may be manually reviewed and committed as fixed data on a later clean head, but production or workflow code must never copy, promote, synthesize, or select them. The later authoritative route must independently reproduce them. An absent tool, incomplete closure, unpinned helper, unsafe extraction, parser mismatch, or missing fact is a mechanism-ADR stop; do not infer from `PATH`, install a moving package, or relabel an `UNQUALIFIED_*` fixture.

No rootfs, fixture, package, or guest-closure discovery is authorized.

### Phase B slice 2: wire only the existing owners

On the manually committed-attestation head, extend only:

- `completion_kata_operation.py`;
- `completion_kata_process.py`;
- `completion_kata_inputs.py`;
- `completion_kata_network.py`;
- `completion_kata_runtime.py`;
- `completion_kata_ssh.py`;
- `completion_kata_coordinator.py`; and
- `run-stage2-completion-remote.sh`.

Claim the independently reproduced sealed preflight before opening an owner. Reuse the retained rootfs lease, existing operation journal, process supervisor, input owner, fixed `/30` network owner, private containerd/Kata runtime owner, SSH owner, and coordinator. Complete the fixed lifecycle and accepted teardown without adding a production module, duplicate owner, compatibility alias, generic command/path/config API, new journal protocol, fallback, retry, alternate rootfs/cache, or second writer/walker.

`completion_kata_actions.py` and `completion_kata_fdmap.py` remain unchanged. A proved omission in either, a needed journal state, or inability to preserve cleanup reserve within existing time bounds is a stop and replan, not transferable allowance.

### Phase B slice 3: one authoritative standalone Kata qualification

Extend only the existing Kata Python/TypeScript companions, Phase A runner/schema, `run-stage2-completion-remote.sh`, and existing Phase A workflow. Freeze one clean exact reviewed head with no unresolved P0–P3 finding, then permit one attempt-1 GitHub local/KVM event for that head.

The run must independently match committed source, host-tool, runtime, network, SSH, KVM, stored-spec, process, share, and fixture attestations before mutation. It must execute the production normal, startup-failure, timeout, interrupt, and durable-recovery paths, including strict authenticated SSH, and require export cleanup plus an independent final proof of restored baselines and zero task, container, shim, QEMU, virtiofsd, private-containerd, namespace, veth/TAP, tc, nft, share, mount, input/control, operation, runtime-temp/cache, rootfs-lease, source, and descriptor residue.

Success establishes authoritative local standalone-Kata Phase B only at that exact revision. It grants no workload, step-3, campaign, production, release, issue-closure, or cloud authority.

## Conditional steps 3–4

These slices are forbidden until Phase B succeeds and the count formula remains strictly below 34,000.

### Slice 1: candidate contract, guest program, and package candidate

Add exactly these new executable production files:

- `deploy/aws-feasibility/remote/completion_runtime_contract.py`;
- `deploy/aws-feasibility/remote/completion_guest_workloads.sh`; and
- `deploy/aws-feasibility/remote/completion_package_candidate.py`.

Add only the fixed data `deploy/aws-feasibility/remote/stage2-completion-runtime-candidate-v1.json`. Narrow existing edits are limited to `completion_kata_actions.py`, `completion_kata_process.py`, `completion_kata_ssh.py`, `completion_kata_operation.py`, and `completion_kata_coordinator.py`.

Implement the plan's closed zero-argument candidate contract and sealed grants; exact verified-stdin guest program with a closed operation set; one retained-rootfs Kata lifecycle; fixed closure probes; one exact Git workload; and package candidates A and B in separate fresh roots with exact build/install flags, equality, immediate deletion, teardown, and independent zero-residue proof. The candidate contract contains no generated `.deb` identity. No warning, extra output, mismatch, partial result, retry, replacement sample, or automatic promotion is accepted.

After exact-head review, permit one attempt-1 event at that head. Its success is required before the manual final pin.

### Slice 2: manual final pin and post-pin reproduction

Manually review the bounded A=B tuple and add only `deploy/aws-feasibility/remote/stage2-completion-runtime-v1.json` on a new clean revision. Production code cannot write or promote it. Allow only narrow final-grant binding changes in `completion_runtime_contract.py`, `completion_package_candidate.py`, `completion_kata_coordinator.py`, and their tests.

The candidate and final routes remain distinct, private, sealed, and zero-argument; no selector, generic transaction runner, promotion command, or second orchestrator is allowed. At a new exact reviewed head, permit one attempt-1 event that independently repeats two fresh builds/installs, matches the final tuple and all input bindings, and proves complete cleanup. Success is required before the full local run.

### Slice 3: one-lifecycle seven-sample local qualification

Add exactly one further executable production file:

- `deploy/aws-feasibility/remote/completion_local_full.py`.

Extend only `completion_guest_workloads.sh`, `completion_kata_actions.py`, `completion_kata_process.py`, `completion_kata_ssh.py`, `completion_kata_operation.py`, and `completion_kata_coordinator.py` for fixed sample identities and results.

The new file is a sealed, zero-argument, local-only orchestrator, not a controller, campaign, or evidence owner. In one Kata lifecycle it executes Git 1–7, package build 1–7, and package install 1–7 in fixed order. Every sample uses fresh paths, matches final pins, and is deleted and proved absent before the next. Reverify immutable inputs at the plan's cuts. Duplicate, skipped, out-of-order, malformed, failed, timed-out, interrupted, cleanup-uncertain, or drifting work aborts all later samples; there are no retries or replacement samples.

At one exact reviewed head, permit one attempt-1 event using production owners for normal, startup failure, Git failure, package-build failure, install failure, per-sample deletion failure, timeout, interrupt, durable recovery, teardown, and independent final zero residue. Success permits only the statement: **authoritative local standalone-Kata qualification and pinned deterministic Git/package workload readiness, stopped at step 5**.

The four executable production files named above are the only new executable production files authorized by this ADR. Phase B may add only its fixed data-only attestation contract and schema; steps 3–4 may add only the two fixed JSON files named above. Data files may contain no policy, branching, commands, path selection, cleanup rules, or generated executable data. No duplicate owner or generic API is authorized.

## Workflow and event authority

The singular reused workflow is the existing Phase A candidate workflow at `.github/workflows/stage2-phase-a-candidate.yml`. It is used for all five hosted gates; do not create or repurpose another workflow. It is **never** the consumed rootfs full-build workflow, job, or route. This decision expressly supersedes any stale steps-3/4-plan clause only to the extent that the clause could be read as forbidding reuse of `.github/workflows/stage2-phase-a-candidate.yml`; the prohibition on repurposing or rerunning the consumed rootfs full-build workflow remains binding.

The trigger must be exactly same-repository `pull_request` with `types: [labeled]`, not `pull_request_target`, and the gate must require all three exact equalities: `github.event_name == 'pull_request'`, `github.event.action == 'labeled'`, and `github.event.label.name == 'security'`. Remove `synchronize` and `reopened` triggers. Do not add `workflow_dispatch`, `push`, `schedule`, another event, or label-presence matching in place of the exact labeled action. Keep concurrency cancellation disabled.

Set workflow permissions to exactly:

```yaml
permissions:
  contents: read
  actions: read
```

No other token permission, secret, personal access token, GitHub App token, or AWS surface is authorized. The ephemeral `${{ github.token }}` may be exposed only to the pre-mutation duplicate-run guard and used only for read-only GitHub Actions workflow-run API queries. It must not be passed to checkout, production code, acquisition/KVM code, or upload steps; persisted credentials remain disabled. Pass it only through a non-echoing environment/header path, never an argument, and never print, persist, cache, or upload the token, request headers, API response, or workflow-run listing. The guard may emit only a categorical pass/fail result and the already-public current run ID.

Every event must bind the event PR head, checked-out `HEAD`, fixed-source revision, and separately recorded full reviewed SHA exactly; run on GitHub-hosted Ubuntu 24.04, Linux amd64, EUID 0, with no job container, fixed action SHAs, no secrets or AWS surface, and `github.run_attempt == 1`. The reviewed workflow revision must contain exactly one literal stage marker from `phase-b-discovery`, `phase-b-authoritative`, `workload-candidate`, `workload-post-pin`, or `workload-full`, set `run-name` exactly to that marker, and bind the same marker into the fixed no-argument route. A label, PR title/body, environment value, caller input, or API result cannot select or alter the stage. The fixed no-argument production entry remains the only authority-bearing entry.

Before acquisition, KVM access, owner opening, or any other authority-bearing host mutation, the guard must exhaustively paginate the workflow-runs API for the exact repository workflow `.github/workflows/stage2-phase-a-candidate.yml`, with exact query event `pull_request` and `head_sha` equal to the event PR head and reviewed full SHA. It must retain only records whose `event`, `head_sha`, and `display_title` exactly equal `pull_request`, that full SHA, and the literal stage marker. It must find the current run in that exact set and require numeric `github.run_id` to equal the earliest (minimum) run ID in the set. Missing or malformed fields, an absent current run, an API/pagination/rate-limit error, inconsistent results, or any inability to prove the minimum fails closed before mutation. Thus removing and re-adding `security` can create a later attempt-1 run, but that run cannot acquire assets, access KVM, open an owner, or mutate qualification state.

For each of the five gates, the first workflow run created for its exact reviewed full head plus exact stage marker consumes that gate's sole event authority. Creation exhausts it regardless of job start or outcome, including success, failure, cancellation, skip, timeout, duplicate detection, or uncertainty. Never rerun the run, relabel or otherwise retrigger the head, select a favorable run, change a stage marker to evade consumption, or use a synchronize/reopen event. A new commit or head does not renew authority under this ADR.

Any later hosted correction requires a new, separately reviewed and accepted narrow correction ADR. It must identify the consumed run ID, exact head and stage, prove the implementation defect exposed by that outcome, bound the exact corrective files/behavior and new reviewed head, preserve the old outcome, and explicitly authorize at most one new event. A no-op, documentation-only, review-only, refactoring-only, unrelated, speculative, infrastructure-outcome, or favorable-outcome-driven change cannot establish that defect or renew an event. Without that accepted correction ADR, corrections may be developed and reviewed locally but no replacement hosted run is authorized. This rule includes `phase-b-discovery`; no discovery replacement is authorized by this ADR.

Record every created event and outcome before stopping, including at least the run ID, attempt, exact workflow, event/action/label, full head, stage marker, contract digests and fixed pins, categorical phase/scenario/sample outcomes, export cleanup, and final residue result. Metadata uploads remain bounded and schema-validated. No raw keys, commands, paths, addresses, logs, caches, rootfs/runtime bytes, source, ledgers, process snapshots, token material, API responses, or run listings may be uploaded.

Retain the existing 90-minute outer timeout, all internal deadlines, non-borrowing cleanup/reporting reserve, and no-cancellation-substitution rule. This ADR changes no timeout, retry, recovery count, cost bound, or cloud boundary.

## Counts, tests, and review gates

Gross additions are measured from each recorded clean predecessor; deletions create no credit. Before and after every slice, record each changed counted file's physical lines and `git diff --numstat`, then recompute the complete ADR 0039 counted set. Count every new schema/validator/renderer and every generic-file addition implementing Stage 2 behavior. A data contract that gains behavior becomes counted and requires a stop/replan.

Phase B retains these non-transferable per-file plan highs:

| Counted file/surface | Gross high |
| --- | ---: |
| `scripts/run-stage2-phase-a-candidate.py` | 220 |
| `completion_kata_qualification.py` | 320 |
| Phase B schema | 220 |
| `completion_kata_operation.py` | 360 |
| `completion_kata_process.py` | 430 |
| `completion_kata_inputs.py` | 260 |
| `completion_kata_network.py` | 280 |
| `completion_kata_runtime.py` | 520 |
| `completion_kata_ssh.py` | 90 |
| `completion_kata_coordinator.py` | 500 |
| `run-stage2-completion-remote.sh` | 20 |
| **Measured plan total** | **3,220** |
| Review contingency | **50** |
| **Absolute Phase B high** | **3,270** |

Unused per-file allowance cannot fund another file. Steps 3–4 retain 800–1,200 gross lines for candidate/final-pin step 3 and 440–700 for local full qualification, with an absolute **1,900-line** total. Remeasure every named new and edited production file separately after each slice. Future steps 5–7 retain 2,060 lines but receive no authority here.

Stop before implementation or the next slice if any per-file/slice high is exceeded, Phase B rises above 3,270, steps 3–4 rise above 1,900, or:

`current no-deletion reserve + revised complete remaining highs >= 34,000`.

Apply the same strict-less-than gate after Phase B and before each steps-3/4 slice. Do not borrow from future work, count deletions as credit, move behavior into excluded files/data/tests/workflows, or raise the cap under this ADR.

At each applicable slice run:

```sh
npm run format:check
npm run typecheck
npm run schemas
npx tsx --test test/aws-stage2-completion-kata-*.test.ts
python3 -I test/aws-stage2-completion-kata-network.py
python3 -I test/aws-stage2-completion-kata-runtime.py
python3 -I test/aws-stage2-completion-kata-s5.py
git diff --check
```

On Linux amd64 also run the process, root-owned operation, and guarded real-input tests from the Phase B plan. Add and run the plan's runtime-contract, guest-workload, package-candidate, and local-full Python/TypeScript companions in their slices; extend existing runtime-closure, input, process, operation, runtime, and S5 tests. Tests must cover exact contracts and source/head binding, duplicate/additional keys, bool/int coercion, `python3 -O`, drift/replacement, malformed/extra/truncated output, deadlines, interruption, unreaped processes, cleanup uncertainty, immediate sample deletion, and final residue. Run `npm run check` before each final exact-head review.

Every event head requires a clean working tree, exact predecessor/head recording, per-file and aggregate remeasurement, fixed-action/trigger/permission review, and one independent exact-range review with no unresolved P0–P3 finding. Any post-review change invalidates that review.

## Mandatory stops and non-authority

Stop immediately for a new production module or file outside the exact list, duplicate owner, generic API, source/tool/runtime/rootfs/fixture/package/KVM/network/SSH/process/share mismatch, timeout increase, retry, fallback, force/lazy/recursive cleanup, unknown-to-absent conversion, residue, uncertain cleanup, attempt above 1, a non-earliest/duplicate run, or any workflow/event/action/label/head/stage mismatch.

**Stop before step 5 regardless of success or spare lines.** Do not create or modify a step-5 controller, campaign/cycle route, completion evidence/renderer/readiness path, or equivalent.

Stop before any AWS credential or `AWS_*` authority, AWS CLI/account lookup, provider, Terraform/OpenTofu, plan, inventory, apply, SSM, deployment, resource, campaign, cloud cleanup, or other cloud action. No timeout, cost, cloud, release, production, or issue-closure authority changes.

This proposed documentation-only ADR creates no implementation, commit, label, event, run, acquisition, KVM action, deployment, campaign, or cloud authority until accepted.
