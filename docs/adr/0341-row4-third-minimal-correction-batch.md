# ADR 0341: Row 4 third minimal correction batch

## Status

Accepted at exact protected main `ed0263c3`.

## Decision

Product run `34747348323` attempt 1 and KVM run `34747349534` attempt 1 failed at this protected source. Both are non-authoritative and grant no pass, probe, reuse, retry, or qualification authority.

Authorize only source correction, focused review, source review, full validation, readiness validation, protected PR CI, and merge. After merge, authorize exactly one fresh first-created attempt-one replacement pair: one Protected product run and one KVM qualification run for the new protected-main bytes. Same-byte retry and H/G/Q remain denied. AWS, OpenTofu, SSM, Docker, KVM, network, and all effects remain denied now.

## Accounting

The existing `governance` task includes this ADR and index only. All caps and the final-HGQ reserve are unchanged.
