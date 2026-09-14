# ADR 0348: Retire the transient H producer generation

## Status

Accepted under the owner's explicit instruction to complete the improved non-AWS chain through Rows 4–10 and stop before the AWS campaign.

## Context

Protected-main `9ae1f21bf655081f03f4e2f3eb890ffa11de9b3e` completed Row 4:

- exact-source Linux/x86_64 Product diagnostics passed empty generation `75947b6e981b7812f3437abf885f4a6a` and nonempty generation `cf51d41456d02b6c8e877a99f4b82206`, then the disposable VM proved zero Docker/process residue and was deleted;
- direct KVM diagnostic runs `34829663322`, `34829670536`, and `34829678314`, each attempt 1 on a distinct fresh runner and generation, passed exact KVM qualification, authenticated image preparation, isolated driver smoke, report validation, namespace/lease cleanup, and receipt retirement without artifact publication;
- protected Product run `34831102547`, attempt 1, passed both candidate profiles and both eight-capability probe profiles with profile-bound receipts, complete retired-generation inventories, and root-controlled pass evidence;
- protected KVM run `34831105333`, attempt 1, passed initial KVM/root/distinct-boot qualification and the complete isolated driver lifecycle, report validation, artifact publication, and namespace/lease cleanup.

Independent readback validated all Product receipt digests, generations, generation locks, source/tree bindings, 16 probe retirements, capability coverage, KVM schemas, and exact source revision. Candidate `9ae1f21b` therefore has Row 4 authority.

The sole first-created producer run for H `9ae1f21b`, run `34831612221` attempt 1, passed admission and exact source preparation but failed before building at closed stage `artifact.redirect.status`. It produced no artifact and grants no producer, rootfs, or downstream authority. The same H and run cannot be retried.

Three subsequent unique local diagnostic generations each downloaded and verified all 16 fixed public artifacts. Initial status observation also found the expected direct OCI metadata responses, OCI 307 redirects, and Debian snapshot 302 redirects. This supports a transient remote response, not a source-contract correction. Diagnostic success cannot rescue the failed producer or authorize a retry.

## Decision

Retire H `9ae1f21bf655081f03f4e2f3eb890ffa11de9b3e` and producer run `34831612221` through this immutable decision and the producer workflow's exact first-created history. Preserve all Row 4 observations as historical exact-source evidence and the producer failure as terminal evidence; grant no reuse or deletion credit. Do not mutate the old Q-authenticated retirement parser or policy in place: replacement G/Q must publish their additive versioned policy and update every authenticated consumer together.

Make no acquisition, retry, redirect, timeout, rootfs, runtime, image, provider, or campaign behavior change. The acquisition path correctly failed closed on an unaccepted remote status, and repeated local diagnostics converged without weakening it.

Establish this decision's protected-main squash result as replacement implementation H only if its sole parent is `9ae1f21b`, all protected checks pass, and its only executable difference is none. Because source identity changes, repeat exact-source Product diagnostics, three fresh direct KVM diagnostics, and exactly one fresh first-created attempt-one protected Product/KVM pair before dispatching one first-created attempt-one producer for replacement H.

Only after that producer passes and is independently audited may a direct-child G bind replacement H and the producer. Publisher, static observation, Q, mixed preflight, and seven-runner qualification remain later rows.

Add this ADR to the existing governance literal task and the existing launcher refusal test to Product. The test accepts only the platform `EPIPE` write-side observation after the child has already returned the exact denial status and all output/state assertions still pass; it does not relax any executable denial. Transfer 1,000,000 unused bytes from local-tofu-ssm to readiness-ci: their byte caps become 7,400,000 and 4,300,000 respectively, while all line caps and the 21,500,000-byte tranche stay unchanged. No source limit, global hard stop, deletion credit, or final-HGQ reserve change. No AWS, provider initialization, OpenTofu, SSM, inventory, deployment, or campaign operation is authorized. Stop immediately before the AWS campaign.
