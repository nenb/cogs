# Stage 3 S3-01 Pi session slice

This slice promotes the Stage 0 Pi embedding spike into the production `SessionPort` adapter without enabling AWS, SSH, Envoy, real auth storage, or local tool fallback behavior.

## Runtime boundary

- The worker explicitly constructs Pi SDK runtime components: in-memory `AuthStorage`, in-memory `ModelRegistry`, internally constructed contained `SessionManager`, locked `ResourceLoader`, in-memory `SettingsManager`, and `createAgentSession()`.
- Authentication is API-key-only and runtime-only. The adapter uses `AuthStorage.inMemory().setRuntimeApiKey(...)` and rejects OAuth/refresh-token paths. Runtime API keys are not read from files, reflected in events, or written to native Pi JSONL.
- Pi resource discovery is disabled. The locked resource loader returns no extensions, skills, prompts, themes, agents files, packages, or repository imports.
- The only active SDK tools are the Cogs custom `read`, `write`, `edit`, and `bash` tools. They are backed solely by injected ports/fakes; no Pi built-in tools or direct host/network fallbacks are registered.

## Session semantics

`src/pi/session.ts` maps the internal API ports to Pi semantics:

- `prompt` starts a Pi turn.
- `steer` queues a Pi steering message.
- `follow_up` queues a Pi follow-up message.
- `abort` calls Pi abort and emits an aborted run event.
- `state` and `entries` are derived from Pi session state and the internally constructed `SessionManager`.

The adapter preserves Pi native v3 JSONL under a derived `<sessionRoot>/<session_id>` directory and supports basename-only contained resume files for the same session ID. Export packaging remains the existing §20.2 injected boundary for the later export workstream; this slice does not publish a new export manifest format. Branch navigation, when exposed for tests/control, uses Pi `navigateTree()` and is forbidden while a run is active.

## Events

The HTTP/SSE layer now emits the canonical `schemas/events-v1alpha1.json` envelope shape:

- server-owned monotonic `seq`
- server timestamp
- configured `session_id`
- `kind`
- `correlation_id`
- object `payload`
- optional `request_id`

There is no ad-hoc `type` field in SSE data. Pi, tool, usage, settled, and aborted signals are forwarded with request/correlation linkage when a run is active. Publication failure is treated as a fail-closed worker condition: the adapter suppresses late events, performs bounded Pi abort/cleanup, rejects future admission, clears runtime credentials, and invokes the configured fatal callback so launch lifecycle can close readiness.

## Test modes

Normal tests use deterministic fake Pi model streams and injected fake tool ports only.

A real-provider smoke script is available but excluded from CI and fails closed unless explicitly enabled:

```sh
COGS_PI_REAL_PROVIDER_INTEGRATION=1 \
COGS_PI_ANTHROPIC_API_KEY=... \
npm run test:pi:real-provider
```

The script does not print credentials and uses temporary runtime-only state.
