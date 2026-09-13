# ADR 0344: Row 4 proactive confirmed-domain batch

## Status

Accepted for source work at exact protected main `fc6d2e3cd4360d463363735b46f37ffd04fe820e`. This revision is superseded as a dispatch candidate before any protected dispatch; it is **not** retired protected evidence.

## Decision

The confirmed SSH handoff, exact product-tool oracle, telemetry graceful-close, fragment-oracle, KVM qualification custody, and SSH readiness-stderr findings form one focused correction batch. The implementation must preserve bounded admission, backpressure, strict evidence, marker/report schema, KVM/root/distinct-boot checks, and all existing caps.

Osito is diagnostic-only. Exact-source KVM r3 reproduced `readiness stderr-nul-cr`; after the quiet-SSH and custody batch, exact `45fa40f1` passed both KVM phases. Product harness attempts before a private containerd either failed before product execution or exercised only diagnostic-modified bytes. A private-containerd run then established that the exact product reached the synthetic Bash program but exhausted its five-second total bound after creating the workspace proof. A later bounded diagnostic proved the deeper image defect: `sshd -T` and the live SSH session contained only `COGS_PROFILE`; OpenSSH uses the first obtained `SetEnv`, so the later proxy/CA directives were ignored. The product-only synthetic timeout is ten seconds with a separate twenty-second observer bound, and the sandbox now emits one combined `SetEnv` directive. A newly published and independently reviewed image identity is required before another product dispatch. None of these Osito results is authority.

Authorize only source changes, focused tests, source/focused reviews, validation, protected PR CI, merge, and disposable Osito diagnostics with unique generations and cleanup. After merge and only after the stated source work/reviews pass, authorize one fresh protected product/KVM first-created attempt-one pair for the new bytes. Same-byte retry and H/G/Q remain denied; GitHub dispatch, AWS, OpenTofu, SSM, deployment, and campaign effects stay prohibited until their explicit later gates.

## Accounting

The `governance` allocation includes this ADR and the ADR index. The `product` task allowlist is extended only to this batch's modified source/tests and the fixed `dev/linux-kvm/qualification-owner.py`/`qualify.sh` ownership path. It remains within the existing product task cap; there is no cap raise, reserve borrowing, transfer, deletion credit, or change to any allocation/source limit/final-HGQ reserve.
