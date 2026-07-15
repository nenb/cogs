# Stage 3 internal API partial boundary

This slice implements only `IMPLEMENTATION.md` §20.2 on top of the Stage 3 launch/lifecycle foundation for S3-01 (#63). It is intentionally not a complete Cogs worker yet.

Included:

- internal HTTP/SSE routes: `/v1/input`, `/v1/abort`, `/v1/events`, `/v1/entries`, `/v1/state`, `/v1/export`, `/v1/shutdown`, `/health/live`, and `/health/ready`;
- per-worker bearer authentication supplied at runtime outside the launch document;
- strict method, route, JSON content-type, unknown-field, request-size, response-size, and correlation-ID handling;
- bounded local duplicate suppression for accepted `/v1/input` request IDs, including concurrent duplicate coalescing;
- legal prompt/steer/follow-up/abort state checks against the injected session port;
- monotonic versioned SSE sequence with bounded replay and explicit replay-gap rejection;
- paged append-order history through authenticated opaque cursors bound to the worker session;
- explicit authenticated export API response marked sensitive;
- lifecycle-backed readiness and fail-closed shutdown behavior.

Excluded until later S3-01 slices:

- `IMPLEMENTATION.md` §20.3 Pi session construction;
- real session storage, SSH, selected Envoy proxy, auth, or audit WAL implementations;
- model-callable raw export or any tool surface;
- production daemon durable idempotency.

The API is wired only to narrow injected ports so tests can exercise protocol behavior without a real model, Pi session, VM, SSH, proxy, auth service, or WAL. Raw export remains reachable only through the authenticated HTTP API and is not exposed as a model-callable tool.
