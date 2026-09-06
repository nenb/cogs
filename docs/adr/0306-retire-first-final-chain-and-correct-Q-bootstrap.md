# ADR 0306: Retire the first final chain and correct Q bootstrap

- Status: Accepted
- Date: 2026-09-06
- Accepted by: Nick Byrne through explicit standing authorization for all non-AWS prerequisite work

## Context

ADR 0305 froze H `8a1b56cfdaf013b27d8ef7a7e2753d3bb2582271` and established G `69987e08cf9454fecf540a4de097f0877155b043`. Producer `34007531193`, publisher `34013328638`, and static observation `34013774850` each passed at attempt 1.

Pre-Q whole-chain review found a dormant production defect before any preflight, formal qualification, provider, or AWS operation. Production executes `completion_campaign_aws_provider.py` from the immutable H source. H's remote bootstrap fetches G and executes G's stager, but the authenticated static package exists only in Q. The proposed uncommitted Q-only provider correction would therefore have been unreachable. No Q candidate was committed or dispatched. The corrected H measures 93,982 conservative retained lines; the mandatory additive v5 package and final evidence cannot safely fit the inherited 94,000-line hard stop.

## Decision

Permanently retire H, G, and the three observations from authorization use while preserving them as historical facts. Correct the provider in a new implementation commit so its remote bootstrap fetches `approval.qualification_revision` only as data, then executes H's fixed stager against Q's fixed v5 package path. A failure-safe ownership-gated trap removes bootstrap custody beneath root-private `/root`. Keep H source preparation separate, and retain approval authentication of H/G/Q and Q ancestry.

Raise only the terminal retained-line hard stop from 94,000 to 94,100 for the exact v5 package and final evidence; all correction-slice highs and the 90,000 preference remain unchanged. After protected checks and provider-free hostile tests pass, run one exact-H no-mint full/readiness diagnostic, then begin one new producer → G → publisher/static → Q chain. Do not reuse any retired artifact or observation.

## Consequences

This correction and all retired observations grant no preflight, formal qualification, AWS, provider, OpenTofu, SSM, inventory, or production authority. The mandatory AWS stop remains unchanged.
