# Stage 3 launch/lifecycle foundation boundary

This slice implements only `IMPLEMENTATION.md` §20.1 for S3-01 (#63). It is intentionally not a runnable Cogs worker yet.

Included:

- strict validation of `schemas/launch-v1alpha1.json` with no coercion, defaults, additional-field removal, or unknown fields;
- immutable validated launch configuration retained only while the lifecycle is ready;
- deterministic lifecycle transitions for start, readiness, fail-closed dependency loss, graceful shutdown, signal-triggered shutdown, normal recycle, bounded shutdown timeout, and emergency hard-deadline shutdown;
- fixed readiness dependencies: session storage, SSH, selected Envoy proxy, auth, and audit WAL;
- injectable signal sources and cancellable scheduler timers, with dependency start/shutdown receiving `AbortSignal`.

Excluded until later S3-01 slices:

- HTTP endpoints from §20.2;
- Pi session construction from §20.3;
- real session storage, SSH, Envoy, auth, or WAL implementations;
- local-tool/direct-network fallback paths.

Readiness is false unless every required dependency has reported ready. Any dependency start failure or dependency loss revokes readiness and starts bounded shutdown. Normal recycle is separate from operator, signal, and dependency shutdown: the configured recycle deadline emits at most one recycle notice and marks recycle pending; `turnSettled()` begins graceful drain only after that pending recycle. If no settled turn arrives, the configured emergency hard deadline forces shutdown. Operator, signal, and dependency shutdown are immediate and do not emit recycle notices.

Startup is guarded before and after every awaited dependency. If shutdown, signal, or dependency loss occurs during startup, later dependencies are not started and cleanup is attempted only for dependencies whose startup was attempted, in deterministic reverse order. The module has no import-time signal registration or process-global side effects; callers must inject signal sources, scheduler, and dependency implementations.
