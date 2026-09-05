# ADR 0301: Retire the H2 producer and correct the static boundary

- Status: Accepted
- Date: 2026-09-05
- Accepted by: Nick Byrne through explicit standing authorization for all non-AWS prerequisite work

## Context

ADR 0300 established protected-main H2 `8e2af4398519ab8d64b7f9e7194f9c116c6f51d9` and corrected the mixed-preflight `/opt` lifecycle. Replacement producer `33972129993`, attempt 1, subsequently passed with artifact `9971564905` and archive SHA-256 `aed0650e1a3dfee145b00ccebec7e4ac4d159177e69cdd79c2bb607a3cabfe2a`.

Before establishing control, whole-chain review found that the prebuilt static workflow checks out H as its workspace and executes H's `stage2-prebuilt-static-control-runtime-boundary.py`. H2 inherited the newer static workflow bytes from the prior G/Q lineage, SHA-256 `4c031ad4d0ef0dbd25e69f721902f019f37b248ca79f88b5fb48cbf63cfe9693`, while its H-owned boundary still pinned the original H workflow SHA-256 `da423b595330633b30da3ba5c3ad603cc23ca5dd31e5a64ebee82f1ea85fa1c7`. Any H2 static observation would therefore fail before source preparation. No H2 publisher or static observation was dispatched. The additive H3 decision makes the tracked source inventory 1,401 files, one above the former 1,400-file bound.

## Decision

Retire producer run `33972129993` and artifact `9971564905` from authorization use. Their successful canonical rootfs observations remain historical facts, but their H2/source identities cannot authenticate a later H revision.

Correct only the H-owned prebuilt static boundary to pin the exact inherited workflow digest `4c031ad4d0ef0dbd25e69f721902f019f37b248ca79f88b5fb48cbf63cfe9693`; bind the portable test to the exact H2 predecessor bytes; raise the measured tracked-file bound narrowly from 1,400 to 1,420; and freeze the protected-main result as H3 after all checks pass. The static workflow must remain byte-identical through later G3 and Q3. Whole-chain review found no other stale fixed digest in the active prebuilt H path.

After protected H3 passes, run exactly one first-created attempt-one H3 producer. Only after two independent audits may a direct-child G3 be established and authorize publisher/static observation. Active old-tuple qualification constants remain intentionally fail-closed until G3 and Q3.

## Consequences

This correction does not reuse H2 authority, weaken exact ancestry, or enter KVM. Failed, retried, missing, or cleanup-uncertain evidence remains non-authorizing. No AWS, provider, OpenTofu, SSM, inventory, or production authority is granted.
