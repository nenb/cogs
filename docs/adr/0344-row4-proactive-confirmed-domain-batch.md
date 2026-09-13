# ADR 0344: Row 4 proactive confirmed-domain batch

## Status

Accepted for source work at exact protected main `fc6d2e3cd4360d463363735b46f37ffd04fe820e`. This revision is superseded as a dispatch candidate before any protected dispatch; it is **not** retired protected evidence.

## Decision

The confirmed SSH handoff, exact product-tool oracle, telemetry graceful-close, fragment-oracle, KVM qualification custody, and SSH readiness-stderr findings form one focused correction batch. The implementation must preserve bounded admission, backpressure, strict evidence, marker/report schema, KVM/root/distinct-boot checks, and all existing caps.

Osito is diagnostic-only. Exact source KVM r3 reproduced `readiness stderr-nul-cr`; debug-modified r6 passed. Neither result is authority. The current Product Osito harness failed before product execution because its `/tmp` restrictions path was untrusted; it has no product result.

Authorize only source changes, focused tests, source/focused reviews, focused validation, protected PR CI, and merge. Do not run product, KVM, full, readiness, Osito, GitHub, network, Docker, AWS, or other effects. After merge and only after the stated source work/reviews pass, authorize one fresh protected product/KVM first-created attempt-one pair for the new bytes. Same-byte retry and H/G/Q remain denied.

## Accounting

The `governance` allocation includes this ADR and the ADR index. The `product` task allowlist is extended only to this batch's modified source/tests and the fixed `dev/linux-kvm/qualification-owner.py`/`qualify.sh` ownership path. It remains within the existing product task's **1,146** remaining lines; there is no cap raise, reserve borrowing, transfer, deletion credit, or change to any allocation/source limit/final-HGQ reserve.
