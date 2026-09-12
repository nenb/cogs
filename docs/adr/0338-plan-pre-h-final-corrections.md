# ADR 0338: Correct the pre-H plan and preserve all effect denials

## Status

Accepted **planning and budget governance only**. This commit authorizes only this
ADR, its index entry, the closed allocation, its checker, and focused governance
validation. It grants no product, KVM, workflow dispatch, Docker, OpenTofu,
OIDC/STS, provider, AWS, SSM, network, inventory, remote-command, readiness,
full-suite, image, release, H/G/Q, or no-mint effect.

`eda2dc499153f3053772790c02ea6d332403742e` / tree
`9ad48a2be811745f0d8032a0a9f52a33c4b2edec` remains a protected product
checkpoint, not H, G, or Q. Every successor is a direct linear child. Added
lines and UTF-8 added-line bytes remain cumulative from that checkpoint: no
delete, rename, copy, compression, net-size, or prior-checkpoint credit.

## Closed accounting and path custody

The historical product allocation is 18,000 lines / 8,000,000 bytes and the
historical remediation allocation is 48,000 / 11,000,000. The separately
allocated prospective matrix is exactly 15,000 / 13,000,000, so the cumulative
product ceilings are **33,000 / 21,000,000** and remediation ceilings are
**63,000 / 24,000,000**. The source ceiling is
`18,763,891 + 24,000,000 = 42,763,891 <= 43,000,000`; tracked files are
`1,420 + 180 = 1,600 <= 1,600`. The hard-line calculation is separately
conservative: the measured current 99,899 leaves 15,100 before strict 115,000;
the 15,000-line matrix is a ceiling, not deletion credit. Each owner and task
ceiling is independent and non-transferable.

The ledger at the review baseline charged 402 lines / 319,440 bytes after the
checkpoint (264 / 27,093 governance, 110 / 8,593 protected-product runtime,
and 28 / 283,754 explicitly identified prior checkpoint work). Those charges
remain charged. The checker now assigns every admitted path to one **named**
task; it has no complement task. It preserves historical owners, including the
integration-owned KVM workflow, and rejects every path not in the exact matrix.

| Named task | Ceiling (lines / bytes) | Exact responsibility |
| --- | ---: | --- |
| pre-H final governance | 1,600 / 1,000,000 | this ADR/index, allocation/checker, governance tests |
| AWS principal denial and cycle custody | 5,000 / 4,800,000 | actual planner, production model/provider/controller/state/receipts, production workflows, schemas/config, and fake tests |
| protected product and KVM contract | 4,000 / 3,200,000 | product custody/runner/snapshot, empty/nonempty and probes, product workflow, KVM driver/qualification and shared `dev/linux-kvm/git-tools.sh` gate |
| generated readiness and no-mint authorization | 2,800 / 3,000,000 | readiness generators/artifacts/tests and the separately reviewed no-mint grant/workflow/tests |
| final H/G/Q control reserve | 1,600 / 1,000,000 | only the enumerated producer/publisher/preflight and retirement-control paths |

The final H/G/Q reserve is deliberately distinct from product, AWS, readiness,
and governance work. The JSON allocation is the authoritative exact path list,
including existing production Python (`completion_campaign_production.py`,
`completion_campaign_aws_provider.py`, controller/state/contracts/receipts),
planner/approval scripts, workflows, schemas, configuration, and fake tests.
It contains a single future immutable
`schemas/aws-stage2-production-principal-contract-v1.json`; no unlisted new
file is allowed. Legacy measurement shell wrappers are **not** repair targets:
they remain denied and non-authorizing unless a later exact static-denial change
is separately budgeted and reviewed.

## Blocking AWS authority contract

Principal separation is **unimplemented and blocking**, not a present mechanical
veto. Until a later source implementation and separately authorized decision,
every production entry point must make an unconditional, pre-credential AWS
deny decision. It must run before reading credentials or package authority and
before OIDC, STS, provider construction, OpenTofu, SSM, network, inventory, or
remote-command code. Thus an old package cannot become executable merely
because an old workflow or a domain-separated hash still parses.

The future immutable authority contract must bind authenticated, individually
verifiable identities for operator, approver/budget/security reviewer, executor,
and zero-inventory observer; their role, expiry, candidate/tree, package, and
contract version are immutable inputs. Missing, equal, expired, stale,
unauthenticated, or representation-only identities deny. A role cannot attest
itself or another role. Tests use fake executables and effect sentinels to prove
that each of those cases, and each stale package identity (H, G, Q, run,
artifact, control, qualification), stops before OIDC/STS/provider/tofu/SSM or
network. Documentation, hashes, and the allocation do not lift this denial.

The future Python route, not the legacy shell route, must establish one durable
cycle intent before any effect; one owner controls that intent, cleanup and
terminal reconciliation. It must not reissue an effect after lost response,
cancellation, crash, or reentry, and it must block a new cycle while state or
cleanup is uncertain. Planner and production provider/controller must use the
same authenticated cycle handle, explicit per-cycle `TF_DATA_DIR`, local backend
metadata, state path, saved-plan identity and custody. They initialize the
backend cross-process before plan/apply compatibility is relied upon and reject
stale, replaced, foreign, or cross-cycle state/plan metadata. Fake-command tests
cover all seven plans, backend initialization, state continuity, crash cuts,
and zero effect reissue; this ADR does not invoke tofu.

For remote validation the production provider first performs bounded SSM
`Online` observation for the exact instance. Under one monotonic overall
deadline it records a durable send intent, sends **exactly once**, durably binds
the returned command/instance receipt, and polls only that pair. Each request is
bounded within the same deadline; known propagation observations are transient,
terminal/mismatched/incomplete observations are fatal. A `Success` observed
after the deadline is rejected. Lost-send response, crash/reentry, propagation,
foreign IDs, response code/output completeness, timeout and cleanup tests prove
one send, no resend, and no late-success acceptance.

## Product and KVM contract to be implemented later

The later implementation has two separate protected fresh runners and
generations: one authenticated `skills=empty` case and one canonical nonempty
shared/user case. Image/build/pass/**failure** receipts authenticate the exact
profile, generation, candidate/tree, image identity, runner, limits and
settlement. They cannot share runner, generation, image tag, publication, state,
or pass authority.

The contract enumerates every admitted input capability and every measured
SSH/SFTP capability. For each it creates a fresh full-minus-one probe with its
own generation, input/mount identity, expected allowed operation and expected
denied operation. SSH and SFTP probes must prove their intended boundary with
successful control and denied-operation oracles, not merely a startup failure.
Missing, substituted, widened, retained, late-failed, or foreign capability
fails before candidate work. Probe receipts aggregate coverage but are never a
candidate pass or dispatch authority.

Both product and KVM produce a bounded, secret-safe failure/uncertainty receipt
independent of a pass receipt: identity, deadline class, cleanup intent,
settlement observations, redacted diagnostics, and quarantine disposition. It
never uploads credentials, raw disks, or workspace images. Hosted runners are
ephemeral: artifact upload is an authenticated handoff of that bounded record,
not proof that local custody survives runner disposal. If handoff or quarantine
cannot complete before disposal, the result is uncertain/failed and cannot pass.

## Later authorization and required order

Merging this plan **never authorizes dispatch**. Product/KVM runs may be
considered only in a later, exact protected-main implementation commit after:
focused validation; independent exact-tree implementation reviews; changed-since
review checks; and the explicitly permitted CI results. That later gate must
mechanically admit the complete profile/probe matrix, sealed execution closure,
limits, image provenance, failure handoff, and the shared `git-tools.sh` gate.
It may authorize only the first-created attempt-one product/KVM runs for that
exact commit. It grants no cancellation replacement, concurrency cancellation,
rerun, retry, or redispatch authority.

The required pre-H order is exact:

1. corrected source;
2. focused tests;
3. the separately authorized protected product/KVM feedback runs;
4. candidate publication and durable readback;
5. separately reviewed no-mint full validation plus generated readiness;
6. recovery/residue validation and two independent audits;
7. final full validation and deterministic regeneration;
8. exact-tree reviews and changed-since-review checks;
9. retirement/freeze decision; then
10. H.

The no-mint pre-H rehearsal binds its exact candidate publication/readback and
may not mint credentials/resources or claim production. It does **not** require
a fresh Q. A later rehearsal after Q, if desired, is a different separately
reviewed authorization.

The intermediate audits are: source/path/budget ownership; production principal
and pre-credential denial; planner/provider state and no-effect sentinels; SSM
one-send/crash recovery; product input/SSH/SFTP probe matrix; KVM shared-gate
and custody; failure-artifact/quarantine; candidate publication/readback;
recovery/residue; generated readiness; and two independent final implementation
audits. Hosted image convergence is explicit: exact image digest/tag and build
provenance converge across empty, nonempty, probe and KVM receipts before the
final full/regeneration gate; any mismatch stops.

After H, only the separately decided direct-child G and fresh Q sequence may
proceed under their own gates. A retirement/freeze decision must enumerate the
superseded H/G/Q/run/artifact identities and preserve their denial. This plan
creates neither effects nor AWS authority.

## Validation for this commit

Run only the central checker, `test/stage2-remediation-budget.test.ts`,
formatting, and diff/path inspection. No product behavior, full/readiness
result, Docker/KVM, OpenTofu/provider/SSM/AWS result, dispatch, or production
claim is made.
