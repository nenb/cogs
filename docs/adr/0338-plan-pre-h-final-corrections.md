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
allocated prospective matrix is exactly **15,127 / 15,000,000**, so cumulative
product ceilings are **33,127 / 23,000,000** and remediation ceilings are
**63,127 / 26,000,000**. The source ceiling is
`18,763,891 + 26,000,000 = 44,763,891 <= 45,000,000`; tracked files are
`1,420 + 200 = 1,620 <= 1,620`. The measured current 99,872 leaves 15,128 before the strict 115,000 hard
limit; the 15,127 forward ceiling remains below it (114,999 maximum), never
deletion credit. Integration's new-file cap is 180
(total 200); it specifically funds the custody schema, fake end-to-end adapter
test, and thirteen fresh v8 control members. Each owner and task ceiling is
independent and non-transferable.

The ledger at the review baseline charged 402 lines / 319,440 bytes after the
checkpoint (264 / 27,093 governance, 110 / 8,593 protected-product runtime,
and 28 / 283,754 explicitly identified prior checkpoint work). Those charges
remain charged. The checker now assigns every admitted path to one **named**
task; it has no complement task. It preserves historical owners, including the
integration-owned KVM workflow, and rejects every path not in the exact matrix.

| Named task | Ceiling (lines / bytes) | Exact responsibility |
| --- | ---: | --- |
| pre-H final governance | 1,100 / 700,000 | this ADR/index and allocation only |
| AWS principal denial and cycle custody | 4,600 / 5,100,000 | actual adapter, planner, production model/provider/controller/state/receipts, custody schema, and fake adapter → provider → recovery tests |
| protected product and KVM contract | 4,000 / 3,200,000 | product custody/runner/snapshot, empty/nonempty and probes, product workflow, KVM driver/qualification and shared `dev/linux-kvm/git-tools.sh` gate |
| generated readiness and no-mint authorization | 1,800 / 2,000,000 | readiness generators/artifacts/tests and separately reviewed no-mint grant |
| final H/G/Q control reserve | 3,627 / 4,000,000 | all equality-test workflow mirrors, fresh v8 controls, H/G/Q guard/staging/qualification schemas and tests |

The final H/G/Q reserve is deliberately distinct from product, AWS, readiness,
and governance work. Its exact list includes all twelve mirrors exercised by
the equality test: rootfs producer and diagnostic producer; rootfs publisher
and diagnostic publisher; static-control candidate; mixed-H/G preflight;
local-Kata qualification; KVM rehearsal and integration diagnostic; and
production plan, approval, and campaign. It also separately funds retirement,
`stage2-prebuilt-local-qualification-guard.py`,
`stage2-stage-prebuilt-control.py`, the formal qualifier/preflight, all three
formal v2 schemas, the pre-AWS package schema, their focused tests, the budget
checker/equality test and formatter configuration, and the complete
thirteen-member fresh v8 control package. It further enumerates the H-owned
consumer closure that the guard seals: fixed-source preparation, hosted mode,
local/native settlement, diagnostic lock, producer, publisher and static-control
boundary scripts; Kata preparation and all three formal-cycle adapters; and the
static-control runtime-boundary test. The AWS task includes the actual
production owner `completion_campaign_aws_adapter.py`, not a substitute
fake-only controller, plus the new Python fake end-to-end
adapter → provider → recovery test and existing adapter/provider tests. Alongside
the existing ADR documents, the only new non-control files are the immutable
`schemas/aws-stage2-production-{principal-contract,custody}-v1.json` and that
fake end-to-end test; no unlisted new file is allowed. Legacy measurement shell wrappers are **not**
repair targets: they remain denied and non-authorizing unless a later exact
mechanical-denial-only change is separately budgeted and reviewed.

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

The future Python route, not the legacy shell route, must use the actual
`completion_campaign_aws_adapter.py` as the sole production custody owner. Its
present `/var/lib/cogs/...` files and flock are only a runner-local cache and
are insufficient: **before any future AWS effect**, implementation must instead
create a deterministic campaign namespace in a pre-existing, independently
administered authenticated custody service. The namespace is the canonical hash
of approval batch, candidate/tree, immutable principal-contract version and
custody-schema version; it contains immutable generation-numbered
`campaign`, `intent`, `receipt`, and hash-chained `journal` records, and one
conditional current-generation pointer. Creation is `if-absent`; every pointer
advance is compare-and-swap on the previous generation and a monotonically
increasing fencing epoch. Local cache disagreement, absent custody, a failed
conditional write, or an unreadable record is uncertainty and denies effects.

The normal executor first authenticates as the contract's executor to acquire a
short lease for the namespace and fencing epoch. A fresh, separately
contract-authenticated recovery owner may acquire the next epoch only after the
old lease expires; every provider/adapter operation carries that epoch and a
deterministic `(campaign, cycle, verb, prior-state)` intent identifier. The old
owner is fenced before its next operation. Recovery reads the external journal,
never trusts runner disk, and may only reconcile each persisted intent by exact
campaign tags/IDs and bounded observational queries. A lost response,
cancellation, runner destruction, missing receipt, or ambiguous normal **or
cleanup** intent is never resent: it remains sticky uncertainty until exact
reconciliation proves its outcome. No new cycle may open while any intent,
resource, cleanup, pointer, or inventory state is uncertain. Cleanup has the
same intent-before-send rule and ends only with a fresh authenticated,
account/region-wide zero-inventory receipt, immutable final settlement, and
credential retirement; custody records remain as the recovery audit trail.

Planner, adapter, and production provider/controller must share that
campaign-bound authenticated handle plus explicit per-cycle `TF_DATA_DIR`,
backend metadata, state path, saved-plan identity and custody. They initialize
the backend cross-process before plan/apply compatibility is relied upon and
reject stale, replaced, foreign, cross-cycle, or fenced state/plan metadata.
Fake end-to-end tests must traverse planner → staging → **actual adapter** →
provider → fresh recovery owner, including runner loss, lease fencing,
generation conflicts, lost normal response, lost cleanup response, exact
reconciliation, no new cycle under uncertainty, and final zero inventory. This
ADR neither provisions the custody service nor invokes tofu/AWS.

For remote validation the production provider first performs bounded SSM
`Online` observation for the exact instance. Under one monotonic overall
deadline it records a durable send intent, sends **exactly once**, durably binds
the returned command/instance receipt, and polls only that pair. Effectful AWS
CLI/SDK transport has `max_attempts=1` (and equivalent environment/configuration
is authenticated); automatic retries are disabled for SSM send, normal effect,
and cleanup effect calls. Observational describe/poll reads may retry only
within the same monotonic deadline and never create/settle an effect intent. Each
request is bounded within that deadline; known propagation observations are
transient, terminal/mismatched/incomplete observations are fatal. A `Success`
observed after the deadline is rejected. Lost-send response, crash/reentry,
propagation, foreign IDs, response code/output completeness, timeout, and
ambiguous normal/cleanup lost-response tests prove one send, no transport retry,
no reissue, and no late-success acceptance.

## Product and KVM contract to be implemented later

The later implementation has two separate protected fresh runners and
generations: one authenticated `skills=empty` case and one canonical nonempty
shared/user case. Image/build/pass/**failure** receipts authenticate the exact
profile, generation, candidate/tree, role-indexed image identity, runner,
limits and settlement. They cannot share runner, generation, image tag,
publication, state, or pass authority. Role-indexed convergence means distinct
profile tags/generations and custody for empty, nonempty, and each probe while
equivalent approved **worker** roles have the same approved content digest and
provenance (and equivalent sandbox roles likewise). It never means one tag or
one image for all roles: the Debian QCOW2 guest and KVM runner identity are
separate authenticated role records and must not converge with OCI worker or
sandbox identities.

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

Merging this plan **never authorizes dispatch**. After reviewed implementation
publication, the only presently permitted automation is the ordinary
same-repository `pull_request` CI for that exact reviewed SHA into protected
`main`: the existing `ci.yml` quality/full test, native, secret-scan, and
current `images` build/scan/SBOM jobs may run and report their normal protected
PR results. `push`, `workflow_dispatch`, product workflow, KVM workflow, and
every Stage2/AWS workflow are not permitted by this plan; no AWS workflow is
created or enabled. Those CI results are evidence only, not product/KVM
execution authority. Product/KVM runs may be considered only in a later, exact
protected-main implementation gate after focused validation; independent
exact-tree implementation reviews; changed-since-review checks; and those
permitted CI results. That later gate must
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
and pre-credential denial; externally durable adapter/provider custody,
fencing, lost-response reconciliation and no-effect sentinels; SSM one-send
transport/crash recovery; product input/SSH/SFTP probe matrix; KVM shared-gate
and custody; failure-artifact/quarantine; candidate publication/readback;
recovery/residue; generated readiness; and two independent final implementation
audits. Hosted image convergence is role-indexed: equivalent approved OCI roles
must match content/provenance while profile tags/generations remain distinct;
QCOW2 guest and KVM runner identities are separately authenticated. Any
mismatch stops.

OpenBao is deferred and nonblocking **only** for narrowed Stage2 synthetic
measurement. The future fixtures must prove no OpenBao availability, identity,
PKI, revocation, Kubernetes, cloud, ordinary admission, or production
qualification; the unresolved fixed OpenBao image remains a Stage3/Stage4 and
production blocker.

After H, only the separately decided direct-child G and fresh Q sequence may
proceed under their own gates. A retirement/freeze decision must enumerate the
superseded H/G/Q/run/artifact identities and preserve their denial. This plan
creates neither effects nor AWS authority.

## Validation for this commit

Run only the central checker, `test/stage2-remediation-budget.test.ts`,
formatting, and diff/path inspection. No product behavior, full/readiness
result, Docker/KVM, OpenTofu/provider/SSM/AWS result, dispatch, or production
claim is made.
