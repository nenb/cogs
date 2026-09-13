# ADR 0343: Row 4 fifth minimal correction batch

## Status

Accepted at exact protected main `c92aaeaa`.

## Decision

Product `34756063319` attempt 1 and KVM `34756064403` attempt 1 failed. Both product probe suites succeeded only for old bytes, but the candidate profiles failed; KVM failed. All results are non-authoritative and non-authorizing.

Authorize only normal source correction, review, validation, protected PR CI, and merge. No effects, full, or readiness execution occurs now. Only after merge, authorize exactly one fresh first-created attempt-one replacement pair: one Protected product run and one KVM qualification run for the new protected-main bytes.

Same-byte retry and H/G/Q remain denied. AWS, OpenTofu, SSM, Docker, KVM, network, and all other effects remain denied.

## Accounting

The existing `governance` task includes this ADR and the ADR index. All caps, allocations, source-inventory bounds, and the final-HGQ reserve are unchanged.
