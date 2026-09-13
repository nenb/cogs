# ADR 0340: Row 4 second minimal correction batch

## Status

Accepted at exact protected main `de0c4ba3fec6f7caf51f198f3f5cea22c31f3d50`.

## Decision

Product run `34741154464` attempt 1 and KVM run `34741155639` attempt 1 failed at this protected source. Both are non-authoritative and are not success, pass, probe, reuse, or retry authority.

This decision authorizes only the minimal source correction, focused tests, source and focused review, full and readiness validation, protected PR CI, and merge. Only after merge it authorizes exactly one fresh, first-created, attempt-one Protected product run and exactly one KVM qualification run for the new protected-main source. Each admission and every effect job requires attempt one. Before effects, admission uses only `actions: read` and `contents: read` GitHub Actions history for its exact workflow, `main`, dispatch event, and candidate; it fails closed unless the current run is the sole first-created exact candidate dispatch in complete bounded pagination. A rerun, reused admission, malformed/unavailable/truncated history, duplicate (including failed or cancelled) candidate run, or later byte after a terminal diagnostic is failure, never replacement authority.

No effect, full, or readiness execution occurs now. Same-byte retry and H/G/Q remain denied. AWS, OpenTofu, SSM, Docker/KVM/network effects remain denied. Cleanup uncertainty remains failure and never becomes reuse authority.

## Accounting

ADR0338's existing `governance` task includes this ADR and the ADR index. Its caps, all other task caps, source-inventory bounds, and the final-HGQ reserve are unchanged.
