# ADR 0289: Correct the first reusable KVM diagnostic

## Status

Accepted.

## Context

Protected-main run `33705783258`, attempt 1, was the first reusable split-lineage KVM diagnostic. The full production-shaped route completed successfully without minting. The readiness route was terminated by its 1,980-second outer command bound even though the sealed lifecycle permits 4,200 seconds of setup, 1,200 seconds for its sole SSH command, and 720 seconds of settlement. Both independent recovery jobs then rejected diagnostic custody at the formal-only executable-policy opener, so settlement and independent residue proof did not run. The run is non-authorizing and grants no cleanup, retry, publication, qualification, production, or AWS claim.

A private Osito reproduction used only digest-verified cached runtime bytes and no authority. It confirmed that the readiness route can still be in its valid setup/runtime-observation interval after 1,980 seconds. Its later QMP classification differed from the successful protected full job, so that private environment result is not a production correction predicate.

## Decision

Give diagnostic recovery a distinct executable-policy opener which validates only the existing split-lineage diagnostic custody projection. Preserve the formal opener's rejection of diagnostic custody and select the opener from the sealed recovery profile rather than caller data.

Make the readiness job and route outer bounds equal to the already reviewed full-route bounds: 250 minutes for the job, 132 minutes for the route step, and 7,800 seconds for the foreground command. These are outer supervision bounds only; they do not extend any journal, command, effect, recovery, or settlement deadline.

After exact-head review and protected CI, another fresh attempt-one reusable diagnostic dispatch is permitted. It remains repeatable and non-authorizing by ADR 0287. Producer, publisher, rehearsal, formal qualification, and every AWS surface remain frozen until both routes, recovery, settlement, scaffolding restoration, and independent zero residue pass and are audited.

## Consequences

Run `33705783258` remains historical failure evidence. No rerun is permitted; a correction uses a new run ID and attempt 1. The private Osito log remains diagnostic-only and cannot establish protected-run behavior or cleanup.
