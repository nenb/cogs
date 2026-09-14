# ADR 0346: Row 4 post-merge Product correction

## Status

Accepted under the owner's explicit instruction to use the improved non-AWS process, complete Rows 4–10, and stop immediately before AWS.

## Observations

PR 546 merged as protected-main `1df3426f099b9beba5e9f4864cacdad49ba0dbdc` after all required CI passed. No protected Product or KVM dispatch consumed those bytes. They are superseded before dispatch, not retired authoritative evidence.

A fresh Linux/x86_64 Lima lane consumed the exact merged source and reviewed stock worker and sandbox images. The unmodified empty Product profile failed closed. Bounded diagnostic-only successor generations established two ordinary runtime defects before any protected dispatch:

- Envoy's `LOGICAL_DNS` resolution selected `[::1]:18443`, while the synthetic Product upstream listened only on `127.0.0.1:18443`. The exact proxy request therefore received an Envoy 503 even though a direct IPv4 TLS request reached the synthetic server.
- The OTLP transport supplied its own `content-length` to Node 22.22.2 `fetch`. Exact equal character, byte, and declared lengths still produced Undici `InvalidArgumentError: invalid content-length header`; removing only that caller-supplied header allowed Fetch to generate the exact request framing and produced 42 trace requests, eight metric requests, 131 exported records, and zero failed or dropped records in the diagnostic generation.

After both diagnostic corrections, the Product tool succeeded with its exact expected bounded result and the worker reached final evidence construction. Extra diagnostic-only paths intentionally prevented that modified generation from granting a pass. Intermittent QEMU-emulated Node signal exits grant no finding, pass, or retry authority. All Lima generations are disposable diagnostics only.

## Decision

Make only these two runtime corrections:

- bind the synthetic Product upstream on the isolated shared network namespace's dual-stack wildcard with `ipv6Only: false`, while retaining the telemetry collector on `127.0.0.1`; this admits Envoy's bounded IPv4-or-IPv6 `AUTO` result without exposing a host interface because the sandbox remains in Docker's `none` network namespace;
- retain the pre-fetch serialized-body byte bound but do not supply a caller-owned `content-length`; require Fetch to frame the immutable string body, and test both absence at the injected-fetch seam and the exact generated header observed by a real local server.

Add focused source-shape coverage for the dual-stack synthetic upstream. Do not alter production route DNS policy, credentials, image definitions, release pins, provider paths, or campaign behavior.

Transfer 200 unused governance lines to Product and add the OTLP source/test paths plus this ADR to the existing allowlists. Governance changes from 6,000 to 5,800 lines and Product from 4,600 to 4,800; the 22,157-line tranche, global hard stop, bytes, local-tofu-ssm allocation, readiness allocation, and final-HGQ reserve are unchanged. There is no deletion credit.

Authorize focused tests, complete local validation, deterministic readiness regeneration, bounded whole-path review, protected PR CI, merge, and fresh disposable exact-source Product and repeated KVM diagnostics. Only after those diagnostics converge may exactly one fresh first-created attempt-one protected Product/KVM pair consume the resulting protected-main candidate. Same-byte retries remain denied.

H, G, Q, AWS, provider initialization, OpenTofu, SSM, inventory, deployment, and campaign effects remain denied until the applicable later rows complete. Work must stop before the first AWS operation.
