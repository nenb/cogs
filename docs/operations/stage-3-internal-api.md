# Stage 3 internal API partial boundary

This slice implements only `IMPLEMENTATION.md` §20.2 on top of the Stage 3 launch/lifecycle foundation for S3-01 (#63). It is intentionally not a complete Cogs worker yet.

Included:

- internal HTTP/SSE routes: `/v1/input`, `/v1/abort`, `/v1/events`, `/v1/entries`, `/v1/state`, `/v1/export`, `/v1/shutdown`, `/health/live`, and `/health/ready`;
- per-worker bearer authentication supplied at runtime outside the launch document; this slice is bearer-only and does not receive, persist, hydrate, refresh, log, or write back rotating refresh tokens;
- strict method, origin-form route, literal loopback-only listen (`127.0.0.1` or `::1`; no DNS-resolved hostnames), JSON content-type, content-encoding, unknown-field, request-size, response-size, duplicate-header, query, and correlation-ID handling;
- validated finite safe positive bounded integer API options, nonzero replay/duplicate capacities, a bounded control-free bearer token of at least 32 UTF-8 bytes, and a bounded session ID;
- bounded local **LRU** duplicate suppression for accepted `/v1/input` request IDs, including exact duplicate recency refresh, concurrent duplicate coalescing, no eviction of pending duplicate entries, and bounded input-queue wait so queued admissions cannot stack into N×port-timeout waits;
- legal prompt/steer/follow-up/abort state checks against the injected session port;
- lifecycle-backed readiness and fail-closed shutdown behavior, including idempotent API close, closed-state readiness reporting where observable, API readiness/admission poison, and exactly-once lifecycle shutdown trigger after any injected port timeout; late noncooperative port completion cannot reopen readiness, write a timed-out response, or allow new event publication;
- monotonic versioned SSE sequence with recursively validated JSON payloads, bounded replay, explicit replay-gap/future-sequence rejection, safe-integer sequence exhaustion guard, bounded event size, and backpressure disconnect;
- paged append-order history through authenticated opaque cursors bound to the worker session;
- explicit authenticated export API response marked sensitive.

Excluded until later S3-01 slices:

- `IMPLEMENTATION.md` §20.3 Pi session construction;
- real session storage, SSH, selected Envoy proxy, auth, or audit WAL implementations;
- model-callable raw export or any tool surface;
- production daemon durable idempotency.

The API is wired only to narrow injected ports so tests can exercise protocol behavior without a real model, Pi session, VM, SSH, proxy, auth service, or WAL. Raw export remains reachable only through the authenticated HTTP API and is not exposed as a model-callable tool.
