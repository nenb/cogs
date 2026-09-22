# ADR 0356: Establish timeout-corrected Q and authorize qualification

- Status: Accepted
- Date: 2026-09-22
- Decider: Nick Byrne
- Scope: exact timeout-corrected H/G static package, mixed preflight, and seven-runner local qualification; no AWS

## Context

ADR 0355 froze timeout-corrected implementation **H**
`d98571b9f2be446ed478464d23df532d91b94e53`. Its protected PR checks,
exact-main CI, bounded unchanged-candidate Linux revalidation, sole producer
`35638724656`, artifact `10658466954`, and independent producer audit passed.
The producer artifact has Actions archive digest
`sha256:b9cc3b2a41b93f683e794f2553aad2d2b8ac5f4a09bcef9718dbf508c7e903fa`
and binds source manifest
`de3adf761aac2a4b7ff33b6064814fe86c2fccd04bd4c3020ce2e7b469e13a3b`,
4,353 entries, and two byte-identical canonical rootfs builds.

Protected control **G** `431f7d2b63b4e5d4da7aca40e0f02ff0fca07f33`, tree
`2bf69423d9c2e9bde7d4d1169619c70383318810`, is one commit whose sole
parent is exact H. Its reviewed candidate tree is equal to the protected
result. PR CI `35651947972`, PR Linux foundations `35651947807`, exact-main
CI `35655767327`, and exact-main Linux foundations `35655767442` all passed
on attempt 1. Independent audit confirmed that the H-to-G change is
strictly governance-only.

The sole first-created trusted publisher `35670440520`, attempt 1, passed
both jobs. Publisher artifact `10670334621` has Actions archive digest
`sha256:5e3554b4cd49947b8171087f5445cb0aee4234fdeb389aad038a97372871d49b`.
Its six members bind descriptor
`da61f77767c81c95c0e06cb047448acfe92b19bb98907cec6e9acc83981967b5`,
publication receipt
`52408b146f2329265d104650133b6be2ac5c9a45304a8114b4ef4609eb6d21b5`,
immutable OCI manifest
`sha256:efe641dfeaa25a44598c7e8ac67c9c468715937782ea19d19299987b91e4b14f`,
exact keyless Sigstore verification, and byte-equal readback of all five
registry members. The independent publisher audit digest is
`sha256:5c8eaec8abf52ad183c9064bbd2acaa96dfbda825fa1e39133e74f4d7ac33dbc`.

Only after that audit passed, the sole first-created no-KVM static
observation `35670986936`, attempt 1, ran at exact G and passed. Artifact
`10670965964` has Actions archive digest
`sha256:1cc6451ad6d77bfdf35fb6b1b919ae83e620858a4c2613e3343f4608e6cfd9d1`
and contains exactly thirteen safe canonical JSON members. Independent
schema validation, production-path validation, exact-H source
reconstruction, workflow-byte checking, and runtime-boundary settlement
accepted:

- static control `06f7446c88f72741a3598aa3a15e990690f87b3180529d66cffbfc0add2eebad`;
- execution envelope `3cdd368820c4eeb5992bab833dcbb1d3e6e598e561390396d9c83ed23284222b`;
- runtime manifest `57c209e20c5151d566b6baea8a8c07dd1bdecf0d6632c64b62c327c4bf84ff00`;
- ten exact executable-closure contracts;
- qualification workflow `0f19740a48e5fcb4c3accf61c9701df5e29e081c25177d4936f5ec7f7ed2d88b`
  and retirement selector
  `6ece9e6cbdd894a60fb2d0e9f0bdc4df2aebc2b4ebf43b96d4a97b4a72802ed2`
  as the only exact G-owned selected-source bridge.

The independent static audit digest is
`sha256:86f84dd3c57dbf71cdcb6f912dd3cc2b1339a14bab84eca7cac0e7aea91af78c`.
No KVM, Kata, provider, OpenTofu, SSM, AWS credential, campaign, or cloud
effect occurred.

## Decision

Replace the historical checked-in v7 package with the exact thirteen
independently read-back members from artifact `10670965964`, byte for byte
and without reserialization, under
`deploy/aws-feasibility/remote/stage2-completion-local-control-v7`.

Fill only the accepted H/G/source/static/descriptor custody constants in
`scripts/stage2-prebuilt-local-qualification-guard.py` and
`scripts/stage2-prebuilt-mixed-hg-preflight.sh`. Preserve the narrow binding
rule: the guard itself is Q's adapter, the qualification workflow and
retirement selector must equal their exact G bytes, and every other selected
source must equal H. Preserve the existing repository-variable and actor
interlocks before every API census or source acquisition. Do not change the
qualification workflow, mixed-preflight workflow, retirement policy,
H-owned runtime, rootfs, image, network, lifecycle, cleanup, provider,
campaign, or production behavior.

Add focused assertions, this decision and index entry, and refresh the
existing deterministic synthetic v4 composition JSON and Markdown goldens
because their commitment chain transitively binds the accepted package. Also
perform only the corresponding deterministic non-authorizing Stage 4 readiness
refresh. Adding this ADR raises the tracked-file source limit from 1,563 to 1,564. The
607-line / 1,700,000-byte pre-H cap, 900-line / 3,500,000-byte post-H reserve,
1,507-line / 5,200,000-byte final-HGQ maximum, source byte limits, and the
five-task allocation of exactly 22,157 lines and 21,500,000 bytes remain
unchanged. No deletion credit applies.

The protected-main squash result becomes qualification revision **Q** only
if it is one commit whose sole parent is exact G, its tree equals the
independently reviewed candidate tree, every required protected check passes,
fresh exact-main checks pass, and the thirteen static members remain exact.
A failed check grants no authority and must be diagnosed rather than blindly
rerun; any unchanged-candidate revalidation requires a causal, documented,
bounded decision.

After Q is established and independently checked, set
`STAGE2_LOCAL_IMPLEMENTATION_HEAD` to H,
`STAGE2_LOCAL_CONTROL_HEAD` to G, and
`STAGE2_LOCAL_QUALIFICATION_HEAD` to Q while preserving
`STAGE2_LOCAL_AUTHORIZED_ACTOR=nenb`.

Then authorize exactly one first-created attempt-one exact H/G/Q mixed
preflight. It must authenticate all custody, perform no KVM operation, settle
twice, and prove zero residue. Only after independent audit accepts that
preflight may exactly one first-created attempt-one seven-runner formal local
qualification run. Its one full ordinal, six readiness ordinals, seven exact
artifact readbacks, aggregate package readback, cleanup, and zero-residue
proof must all pass. Publisher failure, static failure, mixed-preflight
failure, or qualification failure is terminal for its generation: no retry,
stitching, fallback, historical evidence reuse, or arbitrary ordinal resume.

## Consequences

Q, mixed preflight, and local qualification grant no release, Issue 42
closure, AWS, provider, OpenTofu, SSM, inventory, planning, approval,
deployment, or campaign authority. Production planning remains separately
gated by an accepted qualification package, formal bounded IAM readiness,
and the existing Stage 2 prerequisite map.

The accepted static artifact remains a narrow input to Q. Diagnostic and
Stage 4 readiness artifacts remain non-authorizing. Any later production
generation must retain one run, attempt, approval, batch, and evidence
generation and all existing continuation, deadline, cost, cleanup, signature,
and zero-resource constraints.
