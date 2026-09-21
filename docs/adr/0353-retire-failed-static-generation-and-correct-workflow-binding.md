# ADR 0353: Retire failed static generation and correct workflow binding

- Status: Accepted
- Date: 2026-09-21
- Decider: Nick Byrne
- Scope: retire the failed H/G control generation, correct one exact static-boundary binding, and establish a replacement H/G/Q chain; no AWS

## Context

ADR 0352 froze implementation **H**
`5ea2064daa3e62ddbd68fc0f0bb20db1eb0c3f3c` and authorized one direct-child
control generation. PR 566 passed CI `35566270969` and Linux foundations
`35566270993`, then merged as **G**
`4452a96acb1ad31ea8f6b242334f258ce0b0abab`, whose sole parent is H and
whose tree equals reviewed candidate `292894dc30faa195ddff19a4679358e2d56a70d2`.
Exact-G protected-main CI `35568931402` and Linux foundations `35568931413`
passed.

The sole first-created publisher `35572729553`, attempt 1, passed validation,
publication, exact five-member OCI readback, keyless signature verification,
and credential cleanup. Artifact `10627325100` has archive digest
`sha256:108228da0e3235b6ed615d97768b318dce4642830efd7b68754868f70baf3d5c`.
Independent readback accepted its six exact custody members, OCI manifest
`sha256:03e8deb636d88705f0aad6367f09909df532dfad24ae78bc850eb7913c2040a7`,
publication receipt `119de4a6722a63f4ff142decfbb997cca108a7d6a847eb543ea3057cf77551c8`,
and Cosign output
`6aebb8dc569033f3bd6060f33f56c8c49c4e924e1ea5a713bfe1b6728ce038f4`.
An independent clean-home Cosign verification reproduced that output exactly.

The sole first-created static observation `35573039122`, attempt 1, failed
closed before source acquisition at the initial static runtime boundary. Its
cleanup step passed. No rootfs download, immutable acquisition, candidate,
KVM, AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign effect
occurred.

The failure is deterministic and fully localized. Exact H contains static
workflow SHA-256
`dc7cb9f223f82c994ea2666fa88375982bc328e819dc1c4931b84a37bdbd77db`,
while H's boundary executable still requires historical pre-retirement
workflow SHA-256
`3b3d9f95ad41b84bf2480b61a360d52c46d2624298ca8df9e76a3171af814fdb`.
The test normalized additive retirement text back to the historical workflow,
so it did not exercise the bytes that the workflow actually executes after
those additions became part of a later H.

## Decision

Retire H `5ea2064daa3e62ddbd68fc0f0bb20db1eb0c3f3c`, G
`4452a96acb1ad31ea8f6b242334f258ce0b0abab`, producer `35562735335`,
publisher `35572729553`, failed static run `35573039122`, producer artifact
`10622494382`, and publisher artifact `10627325100`. They remain historical
evidence and grant no retry, reuse, downstream authority, or deletion credit.
Q and R were never created.

Preserve retirement V1 byte-identically at SHA-256
`2fe7b704438d9e3f7493ee8be43760ac9f213d095d5411bee137126bc72153b5`
and V2 byte-identically at SHA-256
`035e8c9dc9a8f2a78d1e4360aaf43cde41329771abe222ec7035bfb39dc14c6b`.
Publish closed additive V3, bind it to exact V2, and update all nineteen
pre-effect workflow mirrors together.

Correct only the static boundary's reviewed-workflow commitment to the exact
current workflow bytes after the V3 mirror update. Replace the historical
normalization assertion with an exact current-byte assertion and make the
portable boundary test copy and validate the current source. Update the
qualification guard's exact retirement-selector and qualification-workflow
source seals to the reviewed bytes changed by that mirror update so the
additive V3 veto remains loadable; this is retirement dependency closure, not
qualification authority, and all historical H/G/Q identity and evidence
constants remain blocked. No source-policy, process, descriptor, runtime,
cleanup, provider, or campaign behavior is weakened.

Establish the protected squash result of this correction as replacement **H**
only after its reviewed tree and required protected CI and Linux foundations
pass. This bounded correction does not require another seven-cycle rehearsal,
Product diagnostic sequence, or direct-KVM diagnostic sequence: it changes no
product runtime, rootfs contents, KVM path, provider, AWS adapter, production
campaign, or measured host behavior. Dispatch exactly one first-created
attempt-one producer for replacement H and independently audit it.

After that audit, create one separately reviewed direct-child **G** decision.
Only protected G may authorize one first-created attempt-one publisher and,
after independent publisher audit, one first-created attempt-one static
observation. A failed, cancelled, retried, malformed, expired, mismatched, or
cleanup-uncertain operation retires the replacement generation. Successful
static custody may then support a separate direct-child **Q** decision, one
mixed preflight, and one seven-runner qualification.

Use the existing final-HGQ post-H reserve without changing its 900-line or
3,500,000-byte cap, the combined 1,507-line / 5,200,000-byte allocation, the
22,157-line / 21,500,000-byte tranche, or any task allocation. Add only the V3
policy and this ADR as tracked files, raising the tracked-file source limit
from 1,559 to 1,561 while retaining the 34,000,000-byte source limit.

## Consequences

The previous H/G publisher and static generation is terminal and cannot be
stitched into the replacement chain. Historical successful producer and
publisher evidence does not authorize replacement G, Q, or R.

This decision authorizes only the bounded source correction, tests, readiness
regeneration, protected review/merge, one replacement producer, and the later
separated non-AWS G/Q sequence above. It grants no AWS credentials, planning,
approval, provider initialization, OpenTofu, SSM, inventory, deployment,
campaign, production evidence, release, or Issue 42 closure authority.
