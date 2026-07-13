# Authorization, audit, and revocation fault injector

This trusted-controller fixture exercises Stage 1 proxy hooks without claiming production authorization, WAL, telemetry, or OpenBao integration.

It provides bounded loopback-only HTTP contracts for:

- synchronous authorization that appends an intent before returning `allowed`;
- completion status/latency correlated to exactly one intent;
- authorization outage, audit-unwritable, audit-full/capacity, completion-failure, telemetry-outage, and bounded-delay faults;
- keyed capability validation, immediate deny-new, capability rotation, revocation epoch changes, and drain requests.

Only opaque case/session/route/intent IDs, booleans, status class, bounded latency, sequence, and revocation metadata are retained. Capability plaintext is converted immediately to a keyed digest. Queries, arbitrary fields, credentials, placeholders, request bodies, and capability values are never included in records or responses.

A successful Stage 1 test using this fixture must declare authorization, audit, or revocation as `stubbed` as applicable. Direct OpenBao polling remains stubbed and must be rerun against the real Stage 3 dependency. The injector exists to prove required hooks and fail-closed behavior, not to satisfy production release acceptance.
