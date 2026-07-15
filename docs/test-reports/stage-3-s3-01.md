# Stage 3 S3-01 local evidence

Scope: PR #75 implements the local Pi session adapter slice only. No AWS, SSH, Envoy, real auth persistence, or real provider CI path is exercised.

Evidence from this branch:

- `npm run format:check` passed with ignored `deploy/aws-feasibility/.state/` temporarily moved aside and restored.
- `npm run lint`, `npm run typecheck`, `npm test`, `npm run schemas`, `npm run presets:check`, `npm run images:check`, `npm run lock:check`, `npm run licenses`, and `npm run audit` passed locally.
- Pi adapter tests cover runtime-only API-key delivery, locked discovery, hostile project/global/package canaries, exactly four Cogs tool ports, malformed tool arguments, malformed/oversized tool results, event-schema forwarding through the HTTP/SSE server, abort/timeout/fatal cleanup, readiness revocation through `LaunchLifecycle`, contained same-session resume, and branch navigation behavior.
- Runtime credentials are asserted absent from emitted events and native Pi JSONL; public adapter API exposes no auth storage or model registry.

CI evidence for PR #75:

- Quality and Pi embedding: passed.
- Secret scan: passed.
- Images, vulnerabilities, and SBOMs: passed.
- `insecure-container` and `linux-kvm`: skipped for this PR configuration; these are not claimed as passes for this slice.

Exclusions:

- No AWS campaign or inventory write.
- No SSH/Envoy/real auth storage integration.
- No export-manifest implementation; export remains the existing injected §20.2 boundary for a later workstream.
- Real-provider smoke remains opt-in only and excluded from CI.
