# ADR 0051: Correct ADR 0050 implementation-review findings without adding a candidate

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing bounded-local delegation, after independent hostile review reported no P0–P3 findings.
- Acceptance record: [GitHub pull request #220](https://github.com/nenb/cogs/pull/220).
- Amendment scope: This ADR amends only the implementation, qualification, and counted-line provisions of accepted ADR 0050 that are named below. Every non-conflicting ADR 0050 requirement remains binding.

## Context

ADR 0050 accepted C1–C4 and exactly one operationally selected, non-authoritative Phase A candidate. Implementation reviews found that the proposed patches do not yet satisfy that decision.

The independent C1/C4 review, retained for this decision as `/tmp/adr0050-c1c4-review.md`, reported three P2 findings:

- the purported native-Linux C1 gate could accept a non-Docker container and had no tracked invoker;
- successful recovery compared only the two surviving names rather than the exact full sentinel-and-lock baseline; and
- the **full** offline Docker materializer fault/recovery suite failed at the `directory-open` cut with `.cogs-stage2-rootfs-state-v1` and an `operation-*` directory left beside the sentinel, lock, and ledger.

That review reproduced the same full-suite `directory-open` failure against an untouched archive of exact pristine baseline `0017ac2ec441301a252363b2b9ee90db65fda41e` (`0017ac2`). The smaller Docker builder test is not a substitute. The failure therefore predates the reviewed C1 patch, but it is still a red retained gate; baseline provenance neither waives the failure nor makes it candidate-ready.

The independent C2/C3 review, retained for this decision as `/tmp/adr0050-c2c3-review.md`, reported five P1 findings and one P2 finding:

- writable-descriptor `mount_id` was copied from retained authority rather than independently observed;
- an existing assets directory with an absent partial name could be accepted without a durable successful immediate-cleanup outcome;
- the v2 schema accepted incorrect stage summaries and causally impossible setup evidence;
- the required cut/field matrix used labels and dictionary edits rather than authentic production seams;
- C2 added a generation helper to unauthorized `completion_rootfs_fs.py`; and
- broad rendering/setup handling allowed one malformed surface to suppress unrelated valid evidence.

C4 itself received clean review. The reviews also confirmed that the historical report and v1 schema remained frozen and that no workflow edit was present. Passing portable or Docker-functional tests cannot discharge the missing native-Linux or authentic fault evidence.

The full Docker `directory-open` result exposes one additional narrow rollback defect. A create may have produced a child and then fail before `create-observed`. If local rollback removes that child, removal changes the held chain and parent model. Appending `create-abort` from the pre-removal authority is invalid even when the removal itself was the intended scalar rollback. A correction must derive exact post-removal authority; it must not reinterpret apparent absence as ownership or adopt a later live namespace.

## Decision

If accepted, authorize only R1 and the listed C1–C3 qualification corrections. C4 remains exactly as accepted and reviewed under ADR 0050. This decision adds no transaction state, record kind, candidate, timeout, workflow change, or later-stage authority.

### R1: exact post-removal rollback rebinding

Authorize a narrow correction in `deploy/aws-feasibility/remote/completion_rootfs_builder.py` for the existing create rollback route only when all of these facts hold:

1. the current held authority exactly proves the intended parent and the exact locally created child;
2. failure occurred after that child was created but before its existing `create-observed` record became durable;
3. the existing scalar local rollback removes exactly that proven child through the already held no-follow authority; and
4. stable pre-removal and post-removal observations prove the exact one-name removal, the exact removed-child identity, every required durability boundary, and the exact post-removal parent generation.

After that proof, construct a new chain and rollback model from the exact one-name removal delta. Every affected chain component, parent generation, parent name set, and modeled child/absence fact must be rebound together. The prior chain and model become obsolete and cannot be used or closed as independent authority.

`create-abort` may be appended only from that exact post-removal chain and model authority. Its existing append, `fsync`, hash, offset, legal-state, identity, readback, close, and poisoning rules remain unchanged. R1 does not authorize a paired removal/abort commit, removal of an existing durability barrier, or a new abort meaning.

The following are never rollback authority:

- `ENOENT`, an apparently absent path, or a later directory listing;
- pathname recapture, generic refresh-on-mismatch, or a fresh `_state_chain` adopted into the interrupted operation;
- plan membership, fixed naming, containment, expected bytes, or a prior create intent by itself; or
- an inferred post-removal model assembled after exact continuity was lost.

If removal, post-removal observation, one-name delta, generation rebinding, durability, abort append, sync, readback, or close is failed or uncertain, the in-memory rollback authority is poisoned and discarded. No `create-abort` may be appended from stale or inferred state. A fresh owner must perform the existing complete replay, no-follow walk, and reconciliation and must either recover exactly to the full sentinel-and-lock baseline or preserve uncertainty without additional mutation.

R1 fault tests must execute the real rollback route at every cut from successful child creation through removal proof, model/chain rebinding, abort append, sync, readback, and close. They must prove exact post-removal authority on success and fresh exact recovery or preservation on every uncertainty. The full offline Docker materializer suite's real `directory-open` cut must pass; the known pristine-`0017ac2` failure is not waived and the smaller builder suite cannot replace it.

### C1: tracked native-Linux qualification and exact recovery baseline

Retain ADR 0050's C1 production design and exact 3/2/0 checkpoint. Correct only its qualification route:

- Add one tracked, test-only Linux invoker that begins as an unprivileged caller and uses `sudo` explicitly to invoke the native C1 route. Ordinary portable test wrappers do not count as invocation of this gate.
- Before the test can identify itself as native, the invoker and privileged child must positively prove a shared native host context from kernel-observed namespace and rootfs facts. The proof must cover PID, mount, user, and cgroup namespace authority, the host init/root relationship, and the root mount's identity, source, and filesystem type. It must reject container, nested-namespace, overlay/container-rootfs, changed-root, and ambiguous cases. Linux, EUID 0, absence of `/.dockerenv`, absence of a container marker, or any other apparent absence is insufficient alone or in combination without the positive namespace/rootfs proof.
- The invoker must fail closed if `sudo` provenance, any proof field, or its equality/readback is missing or malformed. It must print the bounded proof classification needed for review without exposing host paths or unrelated host metadata.
- Capture the exact full sentinel-and-lock baseline after each reset and compare it after every successful fresh-owner recovery. The comparison must cover every retained inventory field used by the ownership/generation contract, object kinds and identities, modes and ownership, link counts and sizes, timestamps, and exact sentinel content; comparing names alone is forbidden.

The native route must use real descriptors, names, fork/process boundaries, production builder/recovery code, and real filesystem observations. Deterministic fault seams may choose cuts but may not model filesystem authority. This is a manually invoked tracked local qualification gate; no workflow file or workflow invocation is authorized to change.

### C2: keep authority in the runner and complete the authentic fault matrix

Remove the reviewed C2 additions to `deploy/aws-feasibility/remote/completion_rootfs_fs.py`, including the added generation helper and import. All C2 counted production work must remain in `scripts/run-stage2-phase-a-candidate.py`; unused allowance cannot fund the filesystem helper or another production surface.

Every descriptor participating in writable/retained/named continuity must independently observe its own `mount_id` from that descriptor. In particular, the writable descriptor's value may not be accepted as a parameter copied from retained authority, and the retained, named, fresh-reopen, and cleanup authorities may not borrow one another's value. Compare the independently observed complete generations only after all eleven fields have been obtained from their respective authorities. Add separate authentic writer-side and later-authority mismatch cases for `mount_id`, `dev`, and `ino`.

For every retained non-sealed `asset-partial-final-owned` record whose exact fixed name is absent, cleanup can report success only after exact durable readback of the matching `observation-owned` diagnostic with categorical immediate-cleanup outcome `success`. This rule applies whether the entire assets directory is absent, the directory exists and is empty, or unrelated exactly owned names remain. `not-required`, missing, malformed, mismatched, or uncertain is not success. Later absence, later directory removal, or another owner's cleanup cannot infer or replace the durable immediate outcome.

Replace label-only matrix tests with authentic deterministic seams that execute the named production transition. The suite must prove that each seam was reached and force each ADR 0050 generation field at each applicable writable continuity, retained/name observation, close, journal append/sync/readback, cleanup reopen, final revalidation, pre-unlink, unlink, and post-unlink owned-observation boundary. `fsync`, successful writable close, journal readback, and every cut between unlink and durable `observation-owned` readback require real production seams and asserted outcomes. Include the real native-Linux no-follow same-name replacement and nlink-2 two-name preservation cases. Dictionary mutation, an unused cut label, or repeatedly selecting one common branch is not evidence.

All ADR 0050 prohibitions on initial-partial deletion authority, equal-full-generation privileged ABA claims, adoption, broad cleanup, swallowed errors, and unknown-to-absent conversion remain binding.

### C3: full wire causality and independently bounded rendering/setup tests

The live v2 schema must enforce, rather than leave only to the Python canonicalizer:

- every `stage_evidence` status-to-`checks` mapping in every legal branch;
- the complete artifact-cache/runtime-assets causal matrix;
- zero elapsed time and empty runtime assets where ADR 0050 requires them;
- the causal relationship between `first_build_setup`, cache stage selection/completion, rootfs phase progress, rootfs settlement, and runtime-asset selection; and
- rejection of every impossible boundary, including cache `failure` with setup `complete`, cache `success` with a failed cache summary, or runtime `blocked` with a passing runtime summary.

The schema and canonicalizer must accept the same closed causal state space. Add positive and negative schema tests for every status/summary mapping, every allowed and forbidden cache/runtime pair, every setup transition boundary, and each adjacent impossible state. A broad schema branch that leaves `checks` or setup unconstrained is forbidden.

Production validation and rendering must independently bound rootfs phases, each individual stage row, setup, observation diagnostics, duration, host tools, assets, source identity, KVM facts, cleanup, residue, and each summary. One malformed field may change only its own fixed diagnostic or summary to `unknown`; it may not erase or rewrite unrelated facts. Missing or malformed stage rows must be bounded before lookup and must still fail the required final schema/export gate rather than raising early or fabricating a row.

Tests must independently inject malformed values into each rendering surface and prove all unrelated validated output remains byte-equivalent. Setup tests must execute authentic boundaries around durable `cache-owned`, the independent repeated `plan.load_verified_build_inputs()` call, `_begin_operation` return, and `_materialize` entry. A timing or instrumentation failure after durable `cache-owned` may not leave setup at the obsolete pre-boundary value. A marker in `completion_rootfs_build.py` is permitted only if the runner cannot otherwise observe those exact boundaries within the counted range; it grants no other build-module change.

The historical canonical report remains exactly 3,255 bytes with SHA-256 `d54c4c08dc3388f7d25426cc3294fed483f8c14438d1daa942053f26816f637e`. The v1 schema remains byte-identical to Git blob `1f16fa0966de9ff2117734dd188c7ffd641ccacf`, SHA-256 `7fb0d1e29f3e3789dcfc4a17e5f753fd7ad88c227f04d15c8003d870d4b72286`. No historical rewrite or v1 renderer is authorized.

## Required baseline, count, and stop

Implementation remains based on exact `0017ac2` or a reviewed descendant whose relevant pre-C1–C4 blobs are byte-equivalent to it. Raw additions are measured against that exact baseline, not against an intermediate reviewed patch. ADR 0050's frozen counted set, no-deletion credit rule, exclusions, and anti-evasion rule remain binding.

The revised exact-baseline ranges are:

| Allowed counted production surface | Authorized purpose | Gross raw-addition range |
| --- | --- | ---: |
| `deploy/aws-feasibility/remote/completion_rootfs_builder.py` | C1 plus R1 exact rebinding and checkpoint integration | 110–155 |
| `deploy/aws-feasibility/remote/completion_rootfs_build.py` | C3 trusted setup marker, only if required | 0–15 |
| `scripts/run-stage2-phase-a-candidate.py` | C2 authority/cleanup plus C3 bounded evidence/rendering | 260–360 |
| `schemas/stage2-phase-a-candidate-v2.json` | Complete C3 wire causality | 180–240 |
| **Total** |  | **550–770** |

No other counted production file is authorized. Tests, the tracked native invoker, C4, documentation, and frozen reports remain excluded and create no cap credit. Deletions offset neither a surface nor the total.

Using ADR 0050's exact-baseline no-deletion reserve of **24,683** and unchanged retained later named high of **7,230**, the hard projection is:

`24,683 + 7,230 + 550–770 = 32,463–32,683`.

The projection remains **1,317–1,537 lines below** the unchanged **34,000** hard cap. Stop and replan before further counted implementation if any per-surface high or the **770-line total high** would be exceeded. Unused allowance on one surface cannot fund another. ADR 0050's exact-head remeasurement and `current no-deletion reserve + revised remaining high >= 34,000` stop remain binding.

## Candidate, workflow, and retained exclusions

This decision does **not** add or replace a candidate. It retains exactly the one operationally selected candidate already accepted by ADR 0050. The `security` label must remain absent throughout implementation and review and until the open pull request is frozen at the exact reviewed head. Only then may ADR 0050's one authorized `labeled` event add it. Every consumption, run-attempt, duplicate-run, exact-SHA, durable-record, non-authority, and immediate post-run stop rule remains unchanged.

No workflow edit, trigger change, permission change, timeout increase, retry, rerun, second candidate, fallback, Phase B implementation or execution, step 3 or later implementation or execution, campaign, production use, or issue closure is authorized. No AWS credential, CLI, account lookup, provider, OpenTofu operation, SSM action, deployment, resource creation, cloud cleanup, or other cloud/AWS action is authorized.

Before candidate freeze, all corrected C1–C3 and R1 gates must receive clean implementation and hostile review, the full Docker `directory-open` retained gate must be green, the tracked native-Linux gate must pass with its positive proof and exact baseline, and every retained ADR 0050 verification item must pass. Docker remains functional-only and cannot satisfy native-Linux, KVM, or candidate authority.

This proposed documentation-only decision performs no code, workflow, dependency, lockfile, test execution, network, Docker, KVM, provider, cloud, AWS, candidate, campaign, or production action.

## Consequences

If accepted, R1 can repair the narrow stale-authority rollback exposed by the full materializer suite without treating apparent absence as ownership. C1 obtains an explicitly invoked native qualification gate and exact recovery comparison. C2 remains within its authorized runner surface with independently observed descriptor generations and durable absence semantics. C3's schema and renderer become causally complete and independently fail-closed.

The cost is additional implementation and authentic test work within revised per-surface limits. The sole ADR 0050 candidate remains unconsumed until all gates pass and the exact reviewed pull-request head is frozen; every candidate outcome still requires an immediate stop and replan.
