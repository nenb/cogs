# Potential Browser VM Integration for Cogs and MUTHUR

## A session-isolated browser boundary inspired by Grok Bot

**Status:** Design idea only. None of this is currently implemented. This document grants no cloud, deployment, credential, browser-isolation, production, retry, or release authority.

`COGS.md`, `SECRET-INJECTION.md`, and `DESIGN.md` remain authoritative for Cogs. MUTHUR's `MUTHUR.md` remains authoritative for the platform and security model. If this proposal conflicts with an existing invariant, the invariant wins until an ADR explicitly changes it.

## Summary

A future MUTHUR deployment could give a Cogs-backed agent browser-based access to websites and applications without putting an authenticated browser inside the Cogs worker or its command sandbox.

The preferred design adds a fifth trust role:

```text
MUTHUR             identity, policy, grants, approvals, ordering, lifecycle
Cogs               Pi session and typed browser-tool client
Command sandbox    untrusted filesystem and shell execution
Browser environment hostile web rendering and isolated browser state
Browser broker     trusted automation, credential, profile, and egress enforcement
```

The browser is not a raw Chrome DevTools endpoint exposed to Pi. Cogs receives a small, fixed set of typed browser tools selected before session start. Those tools call an external browser broker bound to the exact MUTHUR session and ownership generation. The broker controls an isolated browser environment, applies network and action policy, and returns bounded protected observations.

The default browser is ephemeral and session-scoped. It shares no cookies, login state, files, or credentials with another Cogs session. Persistent authenticated profiles are a later, explicitly approved capability, not the default.

This preserves the existing division of responsibility:

- MUTHUR decides whether a browser action is authorized.
- Cogs remains the agent worker and canonical Pi-session owner.
- the command sandbox remains credential-free and cannot control the browser directly;
- the browser broker exercises browser authority without disclosing credentials to Cogs or the command sandbox; and
- the provisioner creates and deletes browser resources without receiving prompts or transcript content.

## Motivation

Many useful integrations have no complete or reliable API. Examples include:

- reproducing a browser-only product defect;
- validating a frontend or local application;
- collecting screenshots and accessibility evidence;
- reading a dashboard that has no supported connector;
- completing an administrative workflow that spans several web applications;
- preparing a change in a SaaS UI and stopping before submission; and
- handing a password, passkey, two-factor prompt, or CAPTCHA to the authenticated user.

The existing Cogs egress proxy is appropriate for ordinary HTTP clients and narrow credential-injected API routes. A typed Gatekeeper-style platform tool is preferable for structured integrations. Browser automation fills the remaining gap where the application is defined primarily by a user interface.

A general authenticated browser is much broader than an API tool. It combines:

- arbitrary untrusted web content;
- ambient login state;
- navigation and redirects;
- filesystem upload and download;
- mutable application state;
- difficult-to-classify side effects; and
- a large renderer and protocol attack surface.

It therefore requires its own boundary rather than being treated as a normal Cogs package or a convenience added to `bash`.

## Grok Bot as prior art

This proposal is informed by the public Grok Bot design documented in August 2026:

- <https://docs.x.ai/grok-bot/overview>
- <https://docs.x.ai/grok-bot/computer-and-apps>
- <https://docs.x.ai/grok-bot/skills-routines-and-automations>
- <https://docs.x.ai/grok-bot/approvals-security-and-privacy>
- <https://docs.x.ai/grok-bot/teams-and-enterprises>

Grok Bot demonstrates several useful product ideas:

- a persistent cloud computer with browser, terminal, and files;
- live viewing and human takeover for sensitive login steps;
- durable browser sessions;
- explicit approval cards for consequential actions;
- model-assisted action review;
- recurring browser routines; and
- collaboration between long-lived agents.

The Grok Bot isolation model is not adopted here. Grok Bot assigns one computer per user and shares files, browser sessions, command-line credentials, and application logins across all of that user's Bots. Its documentation explicitly says that separate Bots are not security boundaries.

MUTHUR and Cogs have a different requirement. One active MUTHUR session has one generation-fenced owner and a route-specific effective policy. A browser used by one session must not silently make its authority available to another session, agent, route, tenant, or worker generation.

## Goals

This proposal aims to provide:

1. public and authenticated browser automation without exposing raw browser control to Pi;
2. an isolated browser environment per MUTHUR session by default;
3. credentials, cookies, and browser profiles unavailable to Cogs and the command sandbox;
4. typed browser observations and actions with strict schemas and bounded output;
5. exact policy and approval enforcement for consequential actions;
6. human takeover for passwords, passkeys, two-factor authentication, CAPTCHAs, and equivalent steps;
7. default-deny browser egress with redirect and subresource enforcement;
8. protected screenshot, DOM, download, and upload handling;
9. generation fencing and no automatic retry after an uncertain browser side effect;
10. local functional and authoritative VM-backed security evidence; and
11. a path to scheduled browser routines without turning Cogs into a scheduler or workflow engine.

## Non-goals

This proposal does not authorize:

- a logged-in browser inside the ordinary Cogs command sandbox;
- browser cookies, passwords, OAuth refresh tokens, or profile archives in Cogs;
- direct Chrome DevTools Protocol, WebDriver, VNC, or remote-debugging access from Pi;
- arbitrary JavaScript evaluation as a supposedly narrow browser tool;
- one shared browser profile across all sessions belonging to a user;
- browser text, DOM content, or screenshots becoming trusted control input;
- arbitrary Internet access;
- generic claims that a browser action is safe, reversible, or idempotent;
- automatic retry of an action whose external outcome is uncertain;
- Kubernetes or cloud lifecycle code in Cogs or the browser controller;
- a second platform system of record or workflow engine;
- central logging of URLs, page content, screenshots, form values, or downloaded names; or
- production security claims based on a local container or macOS VM.

## Two distinct browser use cases

### Public or uncredentialed browser testing

Examples include:

- opening a public website;
- testing an application running in the Cogs sandbox;
- running an accessibility check;
- reproducing a frontend bug; and
- capturing screenshots or video evidence.

A first functional implementation may run Playwright or another pinned browser inside the existing untrusted command sandbox, provided:

- it receives no browser profile or integration credential;
- all network traffic remains within the existing default-deny egress contract;
- permitted destinations are immutable launch-time route groups;
- output and downloads are bounded; and
- the result is labelled functional-only until the applicable Linux/KVM security profile passes.

This mode does not establish an authenticated-integration design. It only proves uncredentialed browser behavior.

### Authenticated application integration

Examples include:

- Salesforce, Datadog, Slack, Google Workspace, or a private administration UI;
- a website that requires browser cookies rather than a supported API;
- a multi-application workflow; and
- an operation that requires a human login or verification step.

This mode uses the external browser environment and browser broker described below. Once a browser holds a session cookie, it is a credential exerciser. It must not share the command sandbox's trust boundary or workspace.

## Proposed trust model

```text
Authenticated clients and connector ingress
                    |
                    v
+---------------------------------------------------------------+
| MUTHUR                                                        |
| identity | tenant | route | policy | quota | approval | queue |
+----------------------------+----------------------------------+
                             |
             immutable browser binding and operation context
                             |
                             v
+----------------------------+----------------------------------+
| Cogs trusted worker                                           |
| Pi session | fixed browser tools | canonical JSONL            |
+----------------------------+----------------------------------+
                             |
                  authenticated typed tool call
                             |
                             v
+----------------------------+----------------------------------+
| Trusted browser broker/controller                             |
| schema validation | policy enforcement | action receipts       |
| profile materialization | takeover gateway | artifact handoff   |
+----------------------------+----------------------------------+
                             |
                  generation-bound control channel
                             |
                             v
+----------------------------+----------------------------------+
| Browser environment                                           |
| browser/renderer | one session profile | no platform identity  |
| no Cogs API | no OpenBao | no Kubernetes API | no other session|
+----------------------------+----------------------------------+
                             |
                    assigned egress proxy
                             |
                             v
                    Approved web applications
```

### MUTHUR

MUTHUR owns:

- authenticated tenant and principal identity;
- browser admission and quota;
- browser desired state;
- binding to a session, operation, route, policy revision, and ownership generation;
- effective browser capabilities;
- durable action and approval records;
- takeover authorization;
- browser profile ownership and revocation metadata;
- normalized user-visible events; and
- recovery classification.

MUTHUR does not parse webpage content to decide what the agent should do. Model-generated actions remain untrusted proposals evaluated against typed policy.

### Cogs

Cogs owns:

- the Pi session;
- the fixed launch-time browser tool definitions;
- bounded conversion between Pi tool calls and the browser contract;
- propagation of operation, session, generation, and trace identity;
- cancellation; and
- storage of browser observations in canonical Pi JSONL when returned to the model.

Cogs does not own:

- browser resource provisioning;
- persistent browser profiles;
- external application credentials;
- browser approval records;
- scheduling;
- tenant identity mapping; or
- browser action replay after failure.

### Browser broker/controller

The broker is a new trusted platform component. It:

- accepts only authenticated, schema-valid calls from an exact Cogs binding;
- verifies session, browser, worker, and policy generations;
- controls the browser through a private automation endpoint;
- applies origin, navigation, action, upload, download, and approval policy;
- materializes profiles through a trusted path;
- writes action intent and result evidence through MUTHUR persistence interfaces;
- returns bounded observations or protected-content references; and
- denies all work when identity, policy, audit, profile, browser, or egress dependencies are unavailable.

The broker must not be loaded from repository code, user configuration, Pi extensions, or mutable workspace content.

### Browser environment

The browser environment processes hostile web content and should be treated as compromisable. It has:

- no Kubernetes service-account token;
- no cloud metadata path;
- no OpenBao path;
- no Cogs API path;
- no MUTHUR administrative path;
- no command-sandbox SSH key;
- no other session's profile or storage;
- no general object-store credential;
- only its assigned automation and egress channels; and
- no general-purpose user shell in authenticated mode.

The renderer may necessarily exercise cookies belonging to its browser profile. The security claim is not that an authenticated browser has no credential. The claim is narrower:

> Cogs, Pi, the command sandbox, another session, and another worker generation cannot read or directly exercise the browser profile or upstream credential. The bound browser can exercise only its session's approved browser authority.

This is a new credential-bearing trust boundary and requires an accepted ADR before implementation.

## Browser binding and lifecycle

A browser binding should include at least:

```text
tenant_id
principal_id
session_id
operation_id or authorized session capability
route_binding_id
worker_environment_id
worker_ownership_generation
browser_environment_id
browser_generation
browser_profile_id, when present
effective_policy_id and revision
origin-group revision
expiry
```

The default lifecycle is:

1. MUTHUR authenticates and authorizes the request.
2. MUTHUR persists browser desired state before provisioning.
3. The provisioner creates an isolated browser environment from a pinned image and shared resource specification.
4. The browser controller verifies revision, identity, network, storage, profile binding, and readiness.
5. MUTHUR binds the browser to the current worker and browser generations.
6. Cogs receives only an opaque browser reference and non-redeemable binding material.
7. Browser actions are accepted only from that exact current binding.
8. Replacement creates a fresh browser generation and fresh controller credential.
9. Old-generation actions, events, and takeover channels are rejected.
10. Ephemeral profile state is destroyed after completion-known cleanup.

A persistent profile is never inferred from prior use. It requires an explicit profile capability and owner-authorized binding.

## Proposed browser tool set

The first authenticated browser contract should remain deliberately small.

### Observation tools

```text
browser_navigate
browser_observe
browser_screenshot
browser_scroll
browser_wait
browser_list_downloads
browser_finish
```

### Interaction tools

```text
browser_click
browser_fill
browser_select
browser_key
browser_upload
browser_download
```

The exact names are provisional. Each tool must have a closed, versioned schema with bounded strings, arrays, nesting, timeouts, and result sizes.

### Explicitly excluded tools

Do not initially expose:

```text
browser_eval_javascript
browser_get_cookies
browser_set_cookies
browser_export_profile
browser_open_devtools
browser_raw_cdp
browser_raw_webdriver
browser_arbitrary_request
browser_read_local_file
browser_write_local_file
```

Arbitrary JavaScript, CDP, or WebDriver access is comparable to `bash` combined with browser ambient authority. If ever supported, it must be treated as a broad capability and denied on restrictive routes.

### Example action intent

```json
{
  "schemaVersion": "cogs.browser-action/v1alpha1",
  "browserId": "opaque-browser-ref",
  "browserGeneration": 7,
  "sessionId": "opaque-session-ref",
  "workerGeneration": 12,
  "operationId": "opaque-operation-ref",
  "action": "click",
  "target": {
    "role": "button",
    "accessibleName": "Send"
  },
  "pageRevision": "sha256:<digest>",
  "timeoutMs": 10000
}
```

The model does not select tenant, principal, policy, route, profile, or generation. Cogs and the broker derive those values from authenticated binding state.

## Observations and hostile content

Browser output may include:

- visible text;
- accessibility-tree fragments;
- page metadata;
- screenshots;
- downloaded documents;
- console summaries; and
- bounded network-failure summaries.

All browser output is untrusted content. It may inform Pi, but it cannot:

- issue MUTHUR controls;
- select a tenant, principal, session, route, skill, model, or profile;
- grant a new origin;
- widen browser or sandbox policy;
- approve an action;
- create a persistent login;
- authorize upload of another artifact; or
- turn text from a page into a privileged platform instruction.

The controller returns bounded observations. Large DOMs, screenshots, videos, and downloads are protected artifacts referenced by opaque ID and digest. Public event streams contain only allowlisted status and action metadata.

## Navigation and egress policy

Browser egress is more complex than command-line HTTP because a single page may use:

- redirects;
- scripts and styles;
- image, font, and media hosts;
- identity providers;
- WebSockets;
- service workers;
- speculative requests;
- DNS prefetch;
- WebRTC; and
- download endpoints.

Each integration therefore uses a versioned origin group rather than an unchecked hostname.

An origin group should describe:

- allowed schemes, hosts, and ports;
- navigation versus subresource hosts;
- permitted redirect edges;
- WebSocket policy;
- upload and download policy;
- whether authentication may be exercised;
- path and method restrictions where enforceable;
- maximum response, download, and bandwidth sizes;
- whether pop-ups or new tabs are allowed; and
- an exact revision and test fixture.

The external network boundary must deny:

- direct destination IP access;
- IPv6 bypass;
- arbitrary DNS;
- cloud metadata;
- Kubernetes APIs and service discovery;
- OpenBao;
- Cogs and MUTHUR internal endpoints;
- another session's browser or proxy;
- UDP and QUIC unless separately justified;
- arbitrary WebRTC;
- nested proxying;
- `file:`, extension, and custom protocols;
- unrestricted WebSockets; and
- redirects to undeclared destinations.

Every redirect is re-authorized. A page loaded from an allowed origin does not grant its links, frames, scripts, or redirects authority automatically.

Authenticated browser traffic should reuse the Cogs egress-conformance principles but have a separate applicability matrix and browser-specific probes.

## Credentials and browser profiles

### Prefer a structured integration

When a reliable connector or Gatekeeper-style tool exists, use it instead of browser automation. A typed API operation is easier to scope, audit, retry, approve, and test.

Browser automation is the fallback for visual or otherwise unsupported workflows, not the default integration mechanism.

### Browser profile as credential

A persistent profile may contain:

- cookies;
- local and session storage;
- service-worker state;
- client certificates;
- cached protected content;
- autofill material; and
- application-specific tokens.

It must be treated as a credential-bearing protected object.

A persistent profile design should:

1. encrypt the profile in dedicated protected storage;
2. scope ownership to exact tenant, principal, integration, and external account;
3. store only opaque profile metadata in ordinary PostgreSQL rows;
4. materialize it directly into the assigned browser environment through trusted infrastructure;
5. provide no profile URL or redeemable secret handle to Cogs or the command sandbox;
6. re-encrypt an updated profile only after a completion-known flush;
7. version profile revisions and reject stale writes;
8. make revocation terminate active browser generations; and
9. support exact deletion independently of deleting a Bot, session, or transcript.

The browser profile must never live in the ordinary project workspace.

### Proxy-side injection where possible

For HTTP APIs and header-based authentication, continue using the external proxy or a typed broker. This can keep the real credential out of the browser environment as well as the command sandbox.

Interactive websites often require cookies created by a login flow. Those cookies necessarily exist in the browser environment. The design must state this residual authority honestly rather than claiming that all browser credentials remain outside the browser.

## Human takeover

Some steps must remain human-controlled:

- password entry;
- passkeys and security keys;
- two-factor and one-time codes;
- CAPTCHAs;
- payment confirmation;
- identity verification; and
- sites that explicitly require a human.

A takeover flow should be:

1. Cogs receives a typed `browser_takeover_required` result.
2. MUTHUR persists the request and authorizes the current principal for the exact browser binding.
3. MUTHUR issues a short-lived, one-use takeover capability bound to tenant, principal, session, browser ID, browser generation, purpose, and expiry.
4. The authenticated web client opens an encrypted remote-view and input channel through a dedicated gateway.
5. The user completes the sensitive step directly in the browser.
6. The value is never sent as chat, ordinary API JSON, telemetry, audit, or Pi tool output.
7. Returning control or disconnecting invalidates the takeover capability.
8. The browser controller reports only a bounded completion state.

The first implementation should support takeover only from the authenticated MUTHUR web client. Connector messages such as `/approve`, pasted passwords, or one-time codes must never complete takeover.

The takeover gateway may use WebRTC or another reviewed remote-display protocol. It must not expose the raw browser automation endpoint or allow access to another browser tab, profile, session, or user.

## Action policy and approval

Browser policy should distinguish at least:

```text
browser.session.create
browser.navigate
browser.observe
browser.input
browser.submit
browser.upload
browser.download
browser.persist-profile
browser.takeover
browser.delete
browser.purchase
browser.publish
browser.permission-change
```

The effective policy remains the deny-wins intersection of platform, tenant, principal, agent, verified origin/route, session, grants, runtime, and browser enforcement capabilities.

A restrictive connector route must not reuse a browser whose profile or origin group exceeds that route's policy. It must use a separate restricted session and browser, replace the browser with compatible authority, use a narrow broker, or reject the operation.

### Exact approval binding

Do not approve vague actions such as:

```text
Allow this agent to click buttons on Salesforce.
```

A consequential browser approval should bind:

- tenant and principal;
- verified request origin and route;
- MUTHUR session and operation;
- worker and browser generation;
- current normalized origin;
- page-state digest;
- target role and accessible name or another stable semantic locator;
- exact action kind;
- resource and external account when identifiable;
- value, upload, or request digest;
- effective policy revision;
- expiry; and
- the browser action-intent ID.

Before exercising approval, the controller revalidates the page, target, origin, browser generation, and policy revision. Any mismatch invalidates the approval and requires a new action intent.

Approval may be required for:

- sending a message or invitation;
- publishing;
- purchasing or transferring value;
- deleting or overwriting data;
- changing permissions;
- changing production systems;
- accepting legal terms;
- uploading protected content;
- persisting a login; and
- downloading a sensitive export.

Approval resumes through a new authorized follow-up or exact broker invocation. It does not mutate or unblock an arbitrary in-flight model call.

### Model review is not enforcement

A model may help describe an action or flag suspicious behavior, but model-based Auto Review is not the authorization boundary. Deterministic policy and typed broker enforcement remain authoritative.

## Uploads and downloads

Browser file transfer must integrate with MUTHUR's protected artifact path.

### Download path

```text
browser download
    -> browser quarantine
    -> size, MIME, and archive-depth checks
    -> malware and unsafe-format checks
    -> encrypted protected storage
    -> immutable artifact digest and provenance
    -> optional separately authorized workspace staging
```

The browser does not write directly into the Cogs project workspace.

### Upload path

```text
existing authorized artifact
    -> exact upload grant
    -> browser controller
    -> one selected browser file input
```

Cogs identifies an upload by artifact reference and digest, not by a path in browser storage or an arbitrary command-sandbox file.

Mid-session staging, browser downloads becoming workspace files, or any second writer to the project workspace crosses MUTHUR's artifact-staging ADR gate.

## Durable action processing and unknown outcomes

A browser click is not reliably idempotent. A successful submit can be followed by a lost response, changed page, browser crash, or controller disconnect.

For each browser action, persist before execution:

- immutable action intent;
- session, operation, worker generation, and browser generation;
- policy decision and grant IDs;
- approval ID when required;
- expected page revision;
- idempotency key when the external application supports one; and
- whether the action is observational or potentially side-effecting.

After execution, record a bounded receipt:

- accepted or rejected;
- dispatched or not dispatched;
- resulting page revision when known;
- protected evidence references;
- completion status; and
- `outcome_unknown` when the external effect cannot be established.

Safe observations may be repeated after normal authorization. A potentially side-effecting action is never automatically repeated merely because the resulting page was not observed.

A browser action with unknown outcome must surface to the user for reconciliation. It must not become an ordinary queued action.

## Cancellation and shutdown

Cancellation is completion-known:

- an action not yet dispatched may be cancelled transactionally;
- navigation or observation may be interrupted when the controller can prove no protected side effect;
- a submitted external action requires a known terminal result before reporting successful cancellation;
- otherwise report `interrupted` or `outcome_unknown`;
- profile flush occurs only after the browser controller reaches a known safe boundary; and
- deletion of compute is separate from proof that profile and artifact cleanup completed.

Do not delete the browser environment merely because Cogs disconnected.

## Protected content and telemetry

The following are protected content and must not enter general logs, traces, metrics, or metadata-only audit:

- complete URLs and query strings;
- page titles derived from user content;
- DOM or accessibility text;
- form values;
- screenshots and video;
- cookies and browser storage;
- request and response bodies;
- clipboard data;
- uploaded and downloaded filenames;
- downloaded content; and
- raw browser or driver errors that may quote any of the above.

Permitted metadata includes bounded values such as:

```text
browser_id
session_id
operation_id
worker_generation
browser_generation
action_kind
origin_group_id and revision
policy_decision_id
decision_code
artifact digest and byte count
duration
outcome
```

Protected observations belong in the Pi transcript or encrypted artifact storage according to the applicable contract. Public MUTHUR events contain only explicit allowlisted projections.

## Resource and process boundaries

A possible MUTHUR repository expansion is:

```text
packages/
├── contracts/                 browser intent/result/profile/takeover schemas
├── browser/                   browser state machines and repository interfaces
├── browser-policy/            capability and action classification
├── browser-controller/        controller client and conformance helpers
└── artifacts/                 download/upload integration

apps/
├── api/                       browser metadata and takeover authorization
├── browser-controller/        typed browser execution service
└── provisioner/               browser desired-state reconciliation

test/
├── browser-contract/
├── browser-adversarial/
├── browser-takeover/
└── browser-egress-conformance/
```

The exact package names are provisional. Existing MUTHUR architecture rules continue to apply:

- contracts are canonical TypeBox/JSON Schema 2020-12 contracts;
- only persistence writes SQL;
- only the provisioner holds Kubernetes credentials;
- no app imports another app;
- browser policy decisions and enforcement points are separate;
- PostgreSQL remains the system of record and durable queue; and
- protected browser data is stored by opaque reference, not inline in ordinary contracts.

Possible database entities include:

```text
browser_profiles
browser_profile_revisions
browser_instances
browser_bindings
browser_action_intents
browser_action_receipts
browser_takeovers
browser_artifact_bindings
```

Every tenant-owned query is tenant-scoped in SQL.

## Deployment model

### Local functional profile

A local container may exercise:

- browser contracts;
- basic automation;
- fake profiles;
- takeover UI wiring;
- artifact flow; and
- controller failure behavior.

It is labelled `insecure-browser-container` or equivalent and provides no browser-isolation claim.

### Authoritative local profile

A Linux/KVM profile should prove:

- browser renderer compromise cannot reach Cogs, MUTHUR, OpenBao, cloud metadata, or another session;
- the browser cannot bypass external egress controls;
- another Cogs or browser generation cannot reuse its controller capability;
- profile material is not visible to the command sandbox;
- browser resources are exactly deleted or left visibly cleanup-required; and
- action outcomes follow the no-replay rule.

### Kubernetes/Kata profile

The production browser resource should use the shared versioned per-session resource specification. MUTHUR must not invent an independent topology if Cogs publishes the applicable artifact.

The browser environment must not be placed as a sidecar inside the command sandbox's Kata Pod. Kata sidecars share one VM and would collapse the intended boundary. A browser receives its own isolation resource and network identity.

Only the provisioner creates, observes, and deletes browser resources.

## Threat and control summary

| Threat | Proposed control | Residual risk |
|---|---|---|
| Prompt injection from webpage | Browser content remains untrusted; typed policy on every action | Agent may misuse every granted action |
| Cookie or profile theft by command sandbox | Separate browser environment and storage; no control path from sandbox | Compromised browser can exercise its own session |
| Cross-session credential reuse | Session/profile/generation binding; separate profile by default | Explicit persistent profiles intentionally carry authority across approved sessions |
| Browser exploit reaches platform | Separate VM, no platform identity, external network controls | Hypervisor/runtime escape remains possible |
| Arbitrary Internet access | Immutable origin groups and external default deny | Approved destinations may receive protected data |
| Redirect or subresource escape | Reauthorize redirect edges and subresource hosts | Complex applications may require broad reviewed host sets |
| Action approval TOCTOU | Bind page digest, target, value, policy, and generations; revalidate immediately | Dynamic pages may invalidate approvals frequently |
| Duplicate external action | Persist intent before dispatch; no replay after uncertain outcome | External state may require human reconciliation |
| Sensitive login in transcript | Human takeover or secure handoff; never ordinary chat | The authenticated website necessarily receives the value |
| Malicious download | Quarantine, scan, digest, protected artifact pipeline | Scanners cannot prove all files safe |
| Profile deletion leaves state | Versioned encrypted profile store and exact cleanup state | Vendor sessions may also require upstream revocation |
| Browser controller compromise | Small fixed protocol, isolated service, least authority, reviewed code | Controller can operate its bound browser and is trusted |

## Suggested delivery order

### Phase B0 — ADRs and contract spike

1. Record the browser trust boundary, credential-bearing profile semantics, and browser topology in an ADR.
2. Decide whether the first tool path is a fixed Cogs tool or a trusted external platform-tool module.
3. Define TypeBox contracts for browser binding, observations, actions, receipts, profiles, and takeover.
4. Build a fake browser controller with malformed results, delayed actions, stale generations, approval expiry, and unknown outcomes.
5. Add policy-monotonicity tests and an enforcement registry for browser capabilities.

### Phase B1 — Public read-only browser

Implement:

- ephemeral browser;
- no login or profile persistence;
- immutable public origin groups;
- navigate, observe, screenshot, scroll, wait, and finish;
- no uploads, downloads, JavaScript evaluation, or raw browser endpoint;
- protected observation references; and
- functional container plus authoritative Linux/KVM egress tests.

### Phase B2 — Session-local application preview

Implement:

- a declared preview-service contract;
- authenticated routing to one session-local application;
- browser-driven screenshots and end-to-end tests;
- no public unauthenticated port;
- no access to Cogs or sandbox administration; and
- completion-known wake, drain, and cleanup.

This provides Amp-Portal-like validation without making the preview service a credentialed external integration.

### Phase B3 — Ephemeral authenticated browser

Implement:

- external browser environment;
- human takeover;
- one session-specific browser login;
- exact action approvals;
- no persistent profile after the session;
- browser-specific default-deny egress; and
- unknown-outcome recovery tests.

### Phase B4 — Persistent integration profiles

Implement only after earlier phases pass:

- encrypted per-principal/per-integration profiles;
- explicit profile grants and revisions;
- immediate revocation and browser replacement;
- exact cleanup and upstream logout guidance;
- profile-concurrency rules; and
- cross-session negative tests.

### Phase B5 — Scheduled browser routines

MUTHUR, not Cogs, adds:

- stable firing IDs;
- no-overlap execution;
- per-routine quota and kill switches;
- bounded execution and browser lifetime;
- stale/no-data behavior;
- exact approval boundaries; and
- no automatic replay after unknown external effects.

## Required ADR gates

Implementation must pause for accepted ADRs before:

1. adding browser tools to Cogs or changing its launch/API/event contract;
2. introducing the browser as a credential-bearing execution boundary;
3. persisting and reusing a browser profile across sessions;
4. adding human takeover and its remote-control protocol;
5. allowing browser downloads or uploads to affect the command workspace;
6. introducing mid-session artifact staging or another workspace writer;
7. independently encoding Kubernetes topology instead of consuming the shared Cogs resource specification;
8. allowing direct browser control from the command sandbox;
9. relaxing default-deny egress, fencing, completion-known cleanup, or unknown-outcome rules; or
10. treating a local container or macOS VM as production browser-isolation evidence.

A design that puts connector, OAuth-refresh, provisioning, integration, or general browser-profile credentials into Cogs or the command sandbox conflicts with existing invariants and must not proceed as an implementation shortcut.

## Acceptance criteria

A production browser integration is not ready until repeatable evidence proves:

1. an unauthenticated or foreign principal cannot create, observe, control, or take over a browser;
2. tenant A cannot discover or access tenant B's browser, profile, artifacts, events, or action records;
3. session A cannot use session B's browser or profile without an explicit separately authorized profile grant;
4. a stale Cogs or browser generation cannot issue actions or persist profile state;
5. the command sandbox cannot reach the browser automation endpoint or read its profile;
6. the browser cannot reach MUTHUR internals, Cogs, OpenBao, Kubernetes, cloud metadata, or another session;
7. direct IP, IPv6, UDP, DNS, WebRTC, redirect, WebSocket, and protocol bypass attempts fail outside declared policy;
8. browser text, DOM, screenshots, downloads, and model output cannot widen policy or approve an action;
9. passwords, passkeys, one-time codes, cookies, and profile material do not enter Pi JSONL, general logs, audit, metrics, or traces;
10. consequential actions require exact approval and stale approvals fail;
11. disconnect after a potentially applied action becomes `outcome_unknown` and is never automatically replayed;
12. downloads enter quarantine and protected artifact storage before optional workspace staging;
13. profile revocation prevents new use and replaces active browser generations within the declared bound;
14. browser replacement and scale-to-zero preserve completion-known state and exact cleanup visibility;
15. central telemetry contains only the browser metadata allowlist; and
16. container evidence remains labelled functional-only while Linux/KVM or Kata evidence supports security claims.

## Open questions

Before implementation, ADRs should resolve:

- whether authenticated browser environments use Kata, a full VM, or a specialized remote-browser provider behind the same contract;
- whether the browser controller and profile materializer are one service or separately isolated processes;
- whether any browser profile may be reused across MUTHUR sessions and, if so, the exact ownership and concurrency model;
- which remote-display protocol supports takeover without exposing the automation API;
- how WebAuthn and physical security keys are forwarded without broad desktop access;
- whether DOM accessibility snapshots or screenshots are the primary observation contract;
- which actions can be classified deterministically as observations versus potential side effects;
- how origin-group presets are authored, reviewed, versioned, and tested;
- whether authenticated application previews and external SaaS browsers use separate profiles and network planes;
- how profile deletion coordinates with upstream logout and revocation;
- how browser usage is accounted independently from model and command-sandbox usage; and
- what maximum tabs, screens, browser environments, bandwidth, storage, and session lifetime the platform will support.

## Recommendation

Start with a public, read-only, ephemeral browser outside the trusted Cogs process. Expose only a small fixed set of typed tools. Prove generation fencing, protected observations, default-deny egress, hostile-content handling, and unknown-outcome behavior before adding login state.

Add authenticated profiles only after the browser is treated honestly as a credential exerciser with its own isolation, profile vault, policy, revocation, takeover, and cleanup contracts.

The central design rule is:

> The model may propose a browser action, but MUTHUR policy and a dedicated browser boundary decide whether and how that action is exercised. Cogs and the command sandbox never receive the browser's upstream credentials or unrestricted control channel.
