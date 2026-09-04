# ADR 0296: Retire the first final pre-H rehearsal generation

- Status: Accepted
- Date: 2026-09-04
- Accepted by: Nick Byrne through the standing instruction to complete every non-AWS prerequisite autonomously and stop at AWS

## Context

Diagnostic publisher `33850962596`, attempt 1, successfully authenticated producer `33837299968` and artifact `9924034454`, published and signed one immutable manifest, pulled it by digest, byte-compared all five members, and uploaded six-member control artifact `9928325265` with Actions digest `sha256:739afce108a1460c719710e9377790096eacd9a08dd57863b505955baba1fb2e`.

The first-created no-mint rehearsal `33851159217`, attempt 1, then authenticated and materialized that publication independently in both jobs. The full route passed after about 91 minutes. Its cleanup-only recovery correctly found no active operation path, but immutable fallback rejected the retained six-member descriptor directory as competing with reviewed formal control. The readiness route reached its obsolete 1,980-second outer command deadline and was terminated before completion; recovery preserved the resulting uncertain operation. Neither job reached independent residue or scaffolding restoration. No evidence or artifact was minted.

The successful reusable diagnostic used an explicitly diagnostic control profile whose fallback authenticates the same six external custody members. The formal prebuilt control already carries their canonical projections in its authenticated envelope, but formal immutable fallback retained the legacy rule that any external descriptor directory competes with embedded control. The rehearsal workflow also retained the older 35-minute readiness bound despite protected observations of 66–80 minutes and the already accepted 132-minute/7,800-second diagnostic and formal qualification bounds.

## Decision

Retire rehearsal `33851159217`, publisher `33850962596`, producer `33837299968`, and their artifacts as a complete non-authorizing generation. They may not be retried, reused, promoted, or supplied to a later workflow.

For formal immutable recovery only when authenticated reviewed control exists and the external descriptor directory remains, load the runtime and custody projection together from one validation of the formal control package and pass that same runtime projection through rollback without rereading control. Require the envelope and runtime manifest to agree on every shared rootfs and descriptor field. Read all six external members relative to one held root directory descriptor, retain every member descriptor through the complete read, and recheck root identity, exact names, and all member identities before acceptance. Require root-owned, mode-0400, single-link members to equal the canonical projections, including the signature-verification digest. Continue to reject dangling custody roots and any changed, missing, extra, non-regular, non-root, linked, mode-drifted, or identity-racing member. Preserve the existing one-member pre-control interruption path and diagnostic profile.

Raise only the rehearsal readiness route step from 35 to 132 minutes and its command deadline from 1,980 to 7,800 seconds, matching the measured and already accepted production-shaped bounds.

The required whole-tail differential review also found and closes pre-dispatch defects rather than discovering them in later KVM runs: the static-control producer now stages only `descriptor.json` before immutable acquisition and the five authenticated adjuncts afterward; no-control recovery authenticates the exact six-member descriptor hash chain; diagnostic and rehearsal residue, scaffolding restoration, and a final supervised observation run unconditionally; formal preparation receives a real nested-timeout reserve; and the formal aggregate uses bounded steps, unconditional cleanup, final outcome enforcement, exact cycle-parent cardinality, and the raw upload-artifact digest format distinct from the prefixed API digest. Standard producer readback now checks the hidden publication sentinel too.

Extend no-KVM tests to prove that changed formal external custody is preserved, exact custody permits cleanup-only immutable recovery, the real `/var/lib/cogs` descriptor tree reaches independent residue verification, static-control ordering is exact, seven-cycle artifact parents reject siblings, and aggregate failures cannot skip cleanup. No further KVM dispatch is permitted until those tests, independent rereview, and protected CI pass.

## Consequences

A later merge forms a new provisional implementation generation and requires a fresh diagnostic dual-build producer, direct-child publisher, and first-created no-mint rehearsal. The retired rootfs bytes remain content-identical facts but carry no authority. This decision grants no final producer, H/G, qualification, provider, OpenTofu, SSM, inventory, campaign, production, or AWS authority.
