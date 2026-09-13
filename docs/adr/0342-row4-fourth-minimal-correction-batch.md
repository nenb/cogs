# ADR 0342: Row 4 fourth minimal correction batch

## Status

Accepted at exact protected main `ee114b7b50c34a9b9f93ea7f4248b426a90bb65f`.

## Decision

Product `34751527567` attempt 1 and KVM `34751528484` attempt 1 failed. The product candidate-pass jobs failed; both complete eight-capability probe jobs succeeded only for old bytes; KVM failed. All are historical, non-authorizing results.

Authorize only the minimal source correction, focused tests, source and focused review, full and readiness validation, protected PR CI, and merge. No effects, full, or readiness execution occurs now. Only after merge, authorize exactly one fresh first-created attempt-one replacement pair: one Protected product run and one KVM qualification run for the new protected-main bytes.

Same-byte retry and H/G/Q remain denied. AWS, OpenTofu, SSM, Docker, KVM, network, and all other effects remain denied. Cleanup uncertainty remains `RetirementUncertain` and never authorizes reuse.

## Accounting

The existing `governance` task includes this ADR and the ADR index. All caps, allocations, source-inventory bounds, and the final-HGQ reserve are unchanged.
