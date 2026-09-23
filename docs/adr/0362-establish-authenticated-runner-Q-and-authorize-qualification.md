# ADR 0362: Establish authenticated-runner Q and authorize qualification

- Status: Accepted
- Date: 2026-09-23
- Decider: Nick Byrne
- Scope: exact authenticated-runner H/G static package, mixed preflight, and seven-runner local qualification; no AWS

## Context

ADR 0361 froze authenticated-runner implementation **H**
`2076c2bd781a663d2b27fa478792fc133fa9fd42`. Its protected PR checks,
exact-main checks, sole producer `35795093115`, artifact `10724846408`, and
independent producer audit passed. The producer artifact has Actions archive
digest
`sha256:0a9c5afdc12f4ccdda6e631d99bfdc6ee75c0092a46711b980baf9179928552c`
and binds source manifest
`f4f4fee0eea79315a7079240a1df0a90e7da52adf3189e33d0326cf5339dbc2a`,
4,353 entries, and two byte-identical canonical rootfs builds.

Protected control **G** `1956ea8da439de2ae137e6ccbc5650ca149fe815`, tree
`88275aa3587a2cd46948a4e57660b03084e16e09`, is one commit whose sole
parent is exact H. Its reviewed candidate tree is equal to the protected
result. PR CI `35804105993`, PR Linux foundations `35804106016`, exact-main
CI `35807556555`, and exact-main Linux foundations `35807556560` all passed
on attempt 1. Independent audit confirmed that the H-to-G change is strictly
governance-only.

The sole first-created trusted publisher `35810787971`, attempt 1, passed both
jobs. Publisher artifact `10729183411` has Actions archive digest
`sha256:a4ed91f9bda712f5054dd3f69656e92a365384da4c3b73947a64b355fdb8d298`.
Its six members bind descriptor
`0ac75bf044aa20fc1b1047a5c0579b6489c1ec19502c0044061a5e1fd1597c2c`,
publication receipt
`20c79c10f40250ddb5cedfe62e787fb15c8d71a8fb2359845f48da5ac758f822`,
immutable OCI manifest
`sha256:7be071c45833755bc72839c4f6d7514fec7b4b03a1a1d341354ba23a00c9b396`,
exact keyless Sigstore verification, and byte-equal readback of all five
registry members. The independent publisher audit digest is
`sha256:0c150bac2b50227ee4a1092ec1c87ef18f31e785288861391a57734c036a69a1`.

Only after that audit passed, the sole first-created no-KVM static observation
`35811001315`, attempt 1, ran at exact G and passed. Artifact `10729578379`
has Actions archive digest
`sha256:4e77986b58e0a5abf262e71a456b8aafbbe2d69ab3e3f20bb30d3f8f15b43ccd`
and contains exactly thirteen safe canonical JSON members. Before source
effects, the run authenticated its assigned `ubuntu-24.04` image as OS
`ubuntu24`, version `20260920.314.1`, official release and tag
`ubuntu24/20260920.314`, release ID `392922326`, and immutable commit
`e75633902841aa5479c759492b73409e6d317f12`. The official release and tag-ref
APIs agreed.

Independent schema validation, production-path validation, exact-H source
reconstruction, workflow-byte checking, and runtime-boundary settlement
accepted:

- static control `b2a4475e9277640dea97dc1d9fcc69eeb9af44175ae9f83faf05ed482e5fa01a`;
- execution envelope V4 `db5219543713b3a9733306d0444a611aad9b9c3a8ba40a6059e037dc0feb95b9`;
- runtime manifest `9a6bca06dd35a60e41b4bc1a1e4edc1227d65110bce4b149ba3958cd4c4d2e19`;
- ten exact executable-closure contracts;
- qualification workflow `e8060741fbd3bf70ffc95ae786db5bb953adf031a0bce5e025db1a1c4f3aff42`
  and retirement selector
  `da1789c2c59f4647676beed83357afdc936f2a2fb9c2dd2778bfa63fe54cb963`
  as the only exact G-owned selected-source bridge.

The independent static audit digest is
`sha256:eced002b08abeac25a7db2cef1cc80815ab01df4e207688bc0f59106f5b56170`.
This independently crosses the live runner-image rollout gate that terminal
run `35733919360` rejected; it does not reinterpret or salvage that run. No
KVM, Kata, provider, OpenTofu, SSM, AWS credential, campaign, or cloud effect
occurred.

## Decision

Replace the checked-in v7 package with the exact thirteen independently
read-back members from artifact `10729578379`, byte for byte and without
reserialization, under
`deploy/aws-feasibility/remote/stage2-completion-local-control-v7`. The
accepted package uses additive execution-envelope V4; historical schema and
package bytes outside this generation remain unchanged.

Fill only the accepted H/G/source/static/descriptor custody constants in
`scripts/stage2-prebuilt-local-qualification-guard.py` and
`scripts/stage2-prebuilt-mixed-hg-preflight.sh`. Preserve the narrow binding
rule: the guard itself is Q's adapter, the qualification workflow and
retirement selector must equal their exact G bytes, and every other selected
source must equal H. Preserve the repository-variable, actor, assigned-image,
and first-created-run interlocks before every API census or source
acquisition. Do not change the qualification workflow, mixed-preflight
workflow, retirement policy, H-owned runtime, rootfs, image, network,
lifecycle, cleanup, provider, campaign, or production behavior.

Reclassify only the existing `biome.json` formatting policy and the product/KVM
correction decision `docs/adr/0341-row4-third-minimal-correction-batch.md` from
`governance` to `product`. Their exact pre-H history moves 23 gross lines and
1,537 bytes without changing retained source, any task or global high, or the
five-task sum.

Add focused assertions, this decision and index entry, and refresh the
existing deterministic synthetic V4 composition JSON and Markdown goldens
because their commitment chain transitively binds the accepted package. Also
perform only the corresponding deterministic non-authorizing Stage 4
readiness refresh. The tracked-source maximum remains 1,564; the source
inventory limits remain 34,000,000 bytes and 262,144 serialized bytes. The
five task line highs remain 8,400, 5,050, 6,300, 400, and 3,800; task byte
highs, the 41,950-line / 29,500,000-byte global highs, and the 78,000-line /
35,000,000-byte remediation highs remain unchanged. No deletion credit
applies.

The protected-main squash result becomes qualification revision **Q** only if
it is one commit whose sole parent is exact G, its tree equals the
independently reviewed candidate tree, every required protected pull-request
check passes, fresh exact-Q protected-main checks pass, and the thirteen
static members remain exact. A failed check grants no authority and must be
diagnosed rather than blindly rerun; any unchanged-candidate revalidation
requires a causal, documented, bounded decision.

After Q is established and independently checked, set
`STAGE2_LOCAL_IMPLEMENTATION_HEAD` to H,
`STAGE2_LOCAL_CONTROL_HEAD` to G, and
`STAGE2_LOCAL_QUALIFICATION_HEAD` to Q while preserving
`STAGE2_LOCAL_AUTHORIZED_ACTOR=nenb`.

Then authorize exactly one first-created attempt-one exact H/G/Q mixed
preflight. It must authenticate its assigned official runner image and all
custody, perform no KVM operation, settle twice, and prove zero residue. Only
after independent audit accepts that preflight may exactly one first-created
attempt-one seven-runner formal local qualification run. Each assigned image
is authenticated independently, so an active official rollout and mixed
authenticated image versions are admissible. The run's one full ordinal, six
readiness ordinals, seven exact artifact readbacks, aggregate package
readback, cleanup, and zero-residue proof must all pass. Publisher failure,
static failure, mixed-preflight failure, or qualification failure is terminal
for its generation: no retry, stitching, fallback, historical evidence reuse,
or arbitrary ordinal resume.

## Consequences

Q, mixed preflight, and local qualification grant no release, Issue 42
closure, AWS, provider, OpenTofu, SSM, inventory, planning, approval,
deployment, campaign, or production authority. Production planning remains
separately gated by an accepted qualification package, formal bounded IAM
readiness, and the existing Stage 2 prerequisite map.

The accepted static artifact remains a narrow input to Q. Diagnostic and
Stage 4 readiness artifacts remain non-authorizing. Any later production
generation must retain one run, attempt, approval, batch, and evidence
generation and all existing continuation, deadline, cost, cleanup, signature,
and zero-resource constraints.
