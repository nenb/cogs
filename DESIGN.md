# Cogs Agent-Layer Design

**Status:** Proposed MVP design  
**Date:** 2026-07-09  
**Authoritative inputs:** `COGS.md`, `SECRET-INJECTION.md`, the decisions recorded in the design discussion, current Pi documentation, and current Nebari Infrastructure Core (NIC) code.

Earlier Nebula designs, previous Nebari Pi packs, and other agent products are prior art only. This design does not inherit their APIs, topology, or requirements.

---

## 1. Summary

Cogs is a small, headless agent worker built by embedding the current `@earendil-works/*` Pi SDK. One Cogs worker owns one active Pi session. An external daemon, designed separately, authenticates users, schedules requests, creates and deletes workers and sandboxes, handles approvals and attachments, and routes events to user-facing channels.

Untrusted commands do not run in the Cogs worker. Pi's `read`, `write`, `edit`, and `bash` tools are replaced with implementations that operate over SSH/SFTP against a separate VM-backed sandbox. The sandbox may run as root and contains no real integration credentials, model credentials, Kubernetes credentials, OpenBao credentials, or certificate-authority private keys.

Outbound sandbox traffic is default-denied outside the VM. Supported HTTP and HTTPS traffic must use a trusted explicit proxy. The proxy validates destination, method, and path, terminates TLS, overwrites a non-secret placeholder with the real credential, and records the request. Real credentials are obtained from OpenBao and exist only in the trusted Cogs/proxy resource.

The MVP preserves Pi's JSONL format, associates Git commits with exact or inferred Pi session entries, exports portable session bundles, discovers platform and user-scoped skills, and emits OpenTelemetry. It deliberately does not build another agent framework, scheduler, workflow engine, policy server, database, or application deployment control plane.

---

## 2. Goals

### 2.1 MVP goals

1. Embed Pi without replacing its agent loop, model registry, retry behavior, compaction, session tree, or JSONL format.
2. Run all model-directed code and filesystem tools behind a mandatory VM boundary.
3. Permit root inside the sandbox without putting real credentials inside it.
4. Allow only explicitly declared HTTP/HTTPS destinations.
5. Inject bearer tokens, API-key headers, and Basic authentication outside the VM.
6. Optionally restrict each destination by HTTP method and path.
7. Persist the user workspace and Pi session state independently of compute lifetime.
8. Associate Git commits and hidden turn checkpoints with Pi session-entry IDs.
9. Export Pi-compatible JSONL session bundles.
10. Discover immutable platform skills and private user skills without executing skill code in the trusted worker.
11. Emit enough OpenTelemetry and audit metadata for user and administrator dashboards.
12. Deploy as a NIC-compatible Helm Software Pack while remaining usable on generic Kubernetes.
13. Scale initially to 20–100 users and approximately 50–250 active sessions.

### 2.2 Deferred, but anticipated

The MVP must leave narrow extension points for:

- best-effort session sanitization;
- filesystem indexing, full-text search, and vector retrieval;
- remote OPA policy decisions;
- application/resource broker tools and approval events;
- authoritative filesystem auditing;
- gRPC credential injection;
- additional authentication and protocol classes;
- warm pools targeting sub-five-second startup;
- app logs, metrics, and trace retrieval through an external broker;
- chat-state restoration and workspace restoration.

These extension points are event and protocol boundaries, not a general plugin framework.

---

## 3. Non-goals

Cogs does not provide:

- authentication or user identity mapping;
- UI, ingress, chat channels, or outbound message formatting;
- worker or sandbox scheduling;
- cross-session queues, retries, concurrency control, or idempotency;
- attachment upload or storage;
- scheduling or cron;
- email, calendars, browsers, Google Workspace, or messaging integrations;
- app deployment in the MVP;
- Kubernetes or cloud credentials to the model or sandbox;
- arbitrary Pi extensions, project packages, or runtime package discovery;
- arbitrary Internet access;
- non-HTTP network protocols in the MVP;
- complete prevention of source exfiltration to an approved destination;
- content/DLP inspection;
- protection against a malicious platform administrator;
- confidential computing;
- a claim that hypervisor escape is impossible;
- full Git/workspace restoration in the MVP;
- a second transcript or model abstraction layered over Pi.

---

## 4. Security contract

### 4.1 Narrow credential guarantee

> A sandbox can exercise an approved credentialed HTTP capability, but cannot read the real credential from environment variables, files, Kubernetes, OpenBao, proxy administration interfaces, or its own outbound request headers.

The sandbox receives only a recognizable, non-secret placeholder. The trusted proxy strips or overwrites it after TLS termination.

This guarantee does **not** prevent the sandbox from:

- asking an approved API to perform an allowed action;
- reading data returned by that API;
- sending source or returned data to an approved destination when the allowed method and path permit it;
- abusing the integration as a confused deputy.

Method and path restrictions reduce this risk but do not provide information-flow control. Model providers also receive source included in model prompts by design.

### 4.2 Trust domains

**Trusted:**

- platform administrators;
- Kubernetes/cloud nodes and their control planes;
- the external daemon;
- the Cogs worker process and its pinned dependencies;
- the trusted egress proxy;
- OpenBao and the integration registry/service;
- the configured model provider for data deliberately sent to it;
- persistent-storage and telemetry infrastructure.

**Untrusted:**

- user prompts;
- model output;
- repository contents, `AGENTS.md`, and dependencies;
- platform and user skills as instruction content;
- all commands and processes in the sandbox;
- tool output returned by the sandbox;
- the sandbox guest kernel and guest root;
- files and network data processed by the model.

### 4.3 Threat/control mapping

| Threat | Primary controls | Residual risk |
|---|---|---|
| Prompt injection | VM isolation, fixed tools, static capability policy, deny-by-default egress | The agent may misuse an allowed capability |
| Secret extraction | Secrets and proxy outside VM; placeholder overwrite; no OpenBao path from guest | Real values exist in trusted worker/proxy memory |
| Source theft | Destination/method/path allowlist; no wildcard egress; no raw protocols | Approved write-capable endpoints can receive source |
| Guest kernel exploit | Separate VM kernel; no trusted component in sandbox | Hypervisor/runtime escape remains possible |
| Lateral movement | Per-session identity, external firewall/CNI policy, no service-account token, no metadata endpoint | Compromise of trusted node is out of scope |
| Resource abuse | VM/cgroup quotas, timeouts, output limits, storage quota, lifecycle limits | Work can consume its granted quota |
| Malicious dependency | Immutable guest base image; installation remains in guest | Dependency can compromise the guest and workspace |
| Skill supply chain | Skills treated as text/data; shared revisions pinned; no host execution | A skill can still prompt-inject the model |
| Session tampering | Trusted control-state storage; Pi JSONL; signed/hashed export manifest | Guest can modify Git and workspace data it owns |

### 4.4 Mandatory invariants

1. The sandbox never receives a Kubernetes service-account token.
2. The sandbox cannot access cloud instance metadata.
3. The sandbox cannot access OpenBao, proxy administration, Cogs internal endpoints, or another session.
4. Sandbox egress is impossible except through its assigned proxy.
5. UDP, including QUIC/HTTP/3, is blocked.
6. IPv6 is either covered by the external policy or disabled.
7. Unsupported destinations, methods, paths, authentication classes, and protocols fail closed.
8. Project extensions and packages are never loaded by the trusted Pi process.
9. No user-controlled code is imported by the Cogs worker.
10. Policy or credential-use audit authorization failure denies the request. Ordinary OTLP delivery failure does not stop a run.

---

## 5. Architecture

```mermaid
flowchart LR
    D[External daemon] -->|authenticated internal API| C

    subgraph T[Trusted session resource]
      C[Cogs worker\nPi SDK + session + policy]
      E[Explicit egress proxy\nimplementation selected by conformance]
      C --- E
    end

    C -->|SSH/SFTP with pinned host key| S
    S -->|HTTP_PROXY / HTTPS_PROXY only| E

    subgraph U[VM-backed sandbox]
      S[Ubuntu/Debian sandbox\nroot allowed]
      W[/workspace]
      SS[/shared/skills read-only]
      US[/user/skills read-only snapshot]
    end

    C -->|model API; trusted path| M[Model providers]
    C -->|scoped workload identity| B[OpenBao]
    E -->|approved HTTP/HTTPS| X[External APIs and registries]
    C --> O[OTLP collector]
    E --> O
    C --> CS[(Trusted session state)]
    S --> WS[(Persistent user workspace)]
```

### 5.1 Logical session resources

One active session consists of two trust domains:

1. **Trusted session resource**
   - Cogs worker;
   - trusted explicit egress proxy;
   - ephemeral proxy configuration and TLS leaf key;
   - model and integration credentials in memory/tmpfs;
   - trusted session-state mount.

2. **Untrusted sandbox resource**
   - one VM boundary;
   - one Ubuntu/Debian-based environment;
   - OpenSSH server and ordinary Unix tooling;
   - selected persistent workspace;
   - read-only skill snapshots;
   - ephemeral root filesystem and `/tmp`.

The external daemon eventually creates and binds both resources. Cogs receives an already-provisioned sandbox endpoint and has no Kubernetes or cloud lifecycle permissions. A standalone development launcher may create the pair for testing, but is not part of the Cogs runtime.

### 5.2 Why SSH/SFTP

SSH is the sandbox protocol rather than a custom guest daemon:

- it is mature, inspectable, broadly available, and well understood;
- SSH command execution implements `bash`;
- SFTP implements file reads and atomic uploads for `read`, `write`, and `edit`;
- one per-session client key and a pinned host key provide mutual binding;
- the provisioner generates and injects the sandbox host key before boot, so the launch document contains an a-priori pin rather than a trust-on-first-use observation;
- no Cogs-specific privileged process is required inside the guest;
- the same contract works for an in-cluster VM and a provider-created cloud VM.

The SSH credential is only a session-scoped capability for that sandbox. It is not an integration credential and grants no access outside the guest.

---

## 6. Runtime and platform profiles

### 6.1 Reference MVP: Kata on KVM-capable Kubernetes nodes

The reference implementation uses a standard Kubernetes Pod with a Kata Containers `RuntimeClass`. The pod is the VM isolation boundary. It contains only the sandbox workload; trusted Cogs or proxy containers must never be sidecars in that pod because Kata sidecars share its VM.

Use dedicated, tainted sandbox nodes with:

- KVM/nested-virtualization support or bare metal;
- a pinned Kata and QEMU version;
- only sandbox workloads scheduled there;
- host/CNI-enforced network policy;
- no privileged host mounts;
- aggressive runtime and node patching.

The first validated target is AWS EKS. AWS added KVM-capable nested virtualization for selected virtual EC2 families in 2026; it is not available on arbitrary instance types. NIC already supports AWS node groups, labels, taints, autoscaling, and storage configuration, so the Cogs integration adds a sandbox node-group profile using a currently supported nested-virtualization family or bare metal. The managed node group must use a custom EC2 launch template with `CpuOptions.NestedVirtualization=enabled`, and the selected EKS node AMI must provide the required KVM modules. Nested-virtualization instances are the preferred candidate for initial cost and elasticity, but Kata compatibility, regional availability, performance, launch-template preservation, and node-image configuration are empirical gates. Bare metal remains the fallback for predictable KVM behavior, with a higher idle-cost floor and coarser scaling.

The authoritative instance-family list is the current [AWS EC2 nested virtualization documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html), not a hard-coded list in Cogs.

Kata is used directly through `RuntimeClass`. The MVP does not require a new sandbox CRD or a separate agent-sandbox control plane.

### 6.2 Typical Hetzner Cloud

Hetzner Cloud VMs do not normally expose nested KVM. Software-emulated QEMU would preserve a VM boundary but is too slow to be the recommended production path for compilation-heavy agents.

The supported Hetzner profile therefore uses a **full Hetzner Cloud VM as the sandbox boundary**, rather than nesting a VM inside a k3s worker:

- trusted Cogs workers remain on the k3s platform;
- one ephemeral Hetzner VM is allocated to an active sandbox;
- the user workspace is a reattachable Hetzner volume or equivalent durable store;
- a provider firewall, which guest root cannot modify, allows only SSH from the bound worker and proxy traffic to the trusted egress endpoint;
- the VM has no cloud API credential and does not join the trusted k3s cluster;
- the same SSH/SFTP and explicit-proxy contracts are used.

Provisioning this VM belongs to the external daemon/runtime provisioner, not Cogs. A small warm pool is required to meet the under-30-second cold-start target. This is a later deployment integration around the same Cogs agent layer, not a second Cogs implementation.

Hetzner dedicated servers can instead run the reference Kata profile.

### 6.3 Other environments

- **GCP and Azure:** Helm and Cogs remain portable, but production support is declared only after validating nested virtualization, Kata, CNI enforcement, storage, and cold start on a dedicated node pool. Current NIC implementations for these providers are not yet equivalent to AWS, so the design does not claim end-to-end support today.
- **Local Linux:** k3s on a KVM-capable Linux host can run the Kata profile.
- **Kind/k3d and macOS:** use an explicitly insecure development driver: a plain container with `sshd` behind the same SSH/SFTP contract. An optional macOS VM may improve functional testing but provides no authoritative host-network/default-deny claim. A KVM-capable Linux workstation or runner is the authoritative local VM security profile.
- **QEMU software emulation:** development/compatibility fallback only, not a production recommendation.

### 6.4 Cluster-scoped installation

The reference pack requires a cluster administrator to install or approve Kata, `RuntimeClass`, privileged runtime DaemonSets, and the dedicated node pool. Ordinary session resources remain namespaced and tightly scoped.

This cost is accepted because a mandatory VM boundary cannot be supplied by an ordinary namespaced chart. The blast radius is reduced with dedicated tainted nodes and no trusted platform workloads on those nodes.

---

## 7. Cogs worker

### 7.1 Pi embedding

The worker uses `createAgentSession()` from the pinned current `@earendil-works/*` release with:

- `SessionManager` for native append-only JSONL;
- `AuthStorage` and `ModelRegistry` for Pi-supported models;
- Pi's built-in retry, compaction, branching, usage, and event behavior;
- a custom resource loader that returns only approved context and skill data;
- four custom VM-backed tools named `read`, `write`, `edit`, and `bash`.

Pi's built-in local tools are not registered. Project extension discovery, global extension discovery, package loading, and runtime installation are disabled. Project instructions and skills may be loaded as untrusted text, never imported or executed by the worker.

Cogs metadata is represented through Pi custom entries where useful and an external sidecar manifest where it must not alter Pi compatibility.

### 7.2 Worker state machine

Cogs does not add a scheduler around Pi:

- when Pi is idle, an input of kind `prompt` starts a turn;
- during streaming, `steer` maps to Pi steering behavior;
- during streaming, `follow_up` maps to Pi follow-up behavior;
- `abort` calls Pi's abort mechanism;
- invalid combinations return a state error.

The daemon chooses delivery semantics and remains authoritative for cross-session ordering, queuing, retries, and idempotency. As cheap defense in depth, each worker keeps a bounded LRU of recently accepted request IDs and returns the prior acceptance result for a duplicate. This cache is not a durable workflow store and cannot replace daemon idempotency. Cogs otherwise only protects its single Pi session from invalid simultaneous mutations.

### 7.3 Launch configuration

The worker receives an immutable, versioned launch document containing non-secret values and secret handles:

```yaml
version: cogs.dev/v1alpha1
user_id: opaque-user-id
session_id: opaque-session-id
workspace_id: opaque-workspace-id
sandbox:
  ssh_endpoint: sandbox.example.internal:22
  ssh_host_key: SHA256:...
  client_key_path: /run/cogs/ssh/id
  proxy_auth_handle: sessions/.../proxy-capability
model:
  provider: anthropic
  id: ...
  credential_handle: users/.../models/anthropic
skills:
  shared_revision: sha256:...
  shared_path: /shared/skills
  user_path: /user/skills
integrations:
  - id: github-clone
    preset_revision: sha256:...
    rules:
      - host: github.com
        port: 443
        methods: [GET, POST]
        path_patterns: ["/*/*/info/refs", "/*/*/git-upload-pack"]
      - host: codeload.github.com
        port: 443
        methods: [GET]
        path_patterns: ["/*"]
      - host: objects.githubusercontent.com
        port: 443
        methods: [GET]
        path_patterns: ["/*"]
    auth:
      type: bearer_header
      header: Authorization
      prefix: "Bearer "
      placeholder: COGS_PLACEHOLDER_GITHUB_CLONE
      secret_handle: users/.../integrations/github
limits:
  cpu: "2"
  memory: 4Gi
  tool_timeout_seconds: 900
  max_tool_output_bytes: 1048576
```

An integration is a group of host, port, method, and path rules because real operations commonly fan out across API, smart-HTTP, artifact, and CDN hosts. The platform ships versioned, conformance-tested presets for common capabilities such as GitHub clone/fetch, PyPI install, and npm install. Administrators may define additional groups, but Cogs does not silently widen a failing preset.

The provisioner resolves `proxy_auth_handle` through a trusted path and injects the same generated capability into the sandbox and its assigned proxy. The sandbox never receives the OpenBao identity or handle used to retrieve it.

The document is validated once. Integration and mount changes require resource replacement in the MVP.

---

## 8. Internal agent protocol

Cogs exposes a small, versioned HTTP API inside the cluster. The daemon authenticates with a per-worker mTLS identity or bearer capability. NetworkPolicy is an additional control, not the sole authentication mechanism.

### 8.1 Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /v1/input` | Submit `prompt`, `steer`, or `follow_up` content |
| `POST /v1/abort` | Abort the active Pi run |
| `GET /v1/events?after=<seq>` | Receive Pi/Cogs events over SSE |
| `GET /v1/entries?after=<entry-id>&limit=<n>` | Page through append-order Pi history for reconnect/UI reconstruction |
| `GET /v1/state` | Return session/run state and model/usage summary |
| `POST /v1/export` | Produce an explicit user-requested session bundle |
| `POST /v1/shutdown` | Flush session state and stop gracefully |
| `GET /health/live` | Process liveness |
| `GET /health/ready` | Pi, storage, sandbox, and proxy readiness |

`POST /v1/input` includes a daemon-generated request ID for correlation. A bounded worker-local LRU suppresses immediate duplicate delivery and returns the previous acceptance result. The daemon must still own durable idempotency across worker restart and must not blindly retry a non-idempotent request whose outcome is unknown.

### 8.2 Events

Events use a monotonically increasing worker-local sequence and include:

- Pi message/stream events;
- tool start/update/end;
- usage updates;
- Git mapping/checkpoint events;
- `approval_required` reserved for future brokers;
- warning/error;
- run settled/aborted;
- shutdown-ready.

Raw Pi event payloads are adapted only enough to add stable versioning and correlation IDs. A bounded replay buffer supports short SSE reconnects; Pi JSONL remains the durable source of truth. After replay-buffer eviction or when reopening a chat, the daemon uses the paged entries endpoint rather than requesting a sensitive full export.

Attachments are prepared by the daemon in the workspace and referred to by path/metadata in the prompt. Cogs does not fetch arbitrary attachment URLs.

---

## 9. VM-backed tools

### 9.1 `read`

- SFTP read from an allowed guest path;
- supports offset and limit;
- enforces response-size limits;
- returns text or an explicit binary-file error/encoding result.

### 9.2 `write`

- uploads to a temporary sibling file through SFTP;
- fsync/rename where supported;
- refuses paths outside configured writable roots;
- enforces input and workspace quotas.

### 9.3 `edit`

- reads through SFTP;
- requires one exact, unique match;
- writes atomically;
- reports mismatch without guessing.

### 9.4 `bash`

- executes through SSH in `/workspace`;
- supports a hard timeout and cancellation;
- streams bounded stdout/stderr updates;
- records exit code, signal, elapsed time, and truncation;
- kills the remote process group on cancellation where possible.

Direct `read`, `write`, and `edit` operations enforce path allowlists. `bash` is intentionally general and can access everything visible inside the guest. Security therefore comes from VM mounts, external network policy, and quotas—not shell-command parsing.

### 9.5 Guest filesystem

```text
/workspace       persistent selected user project, read/write
/shared/skills   pinned platform skill snapshot, read-only
/user/skills     private user skill snapshot, read-only
/tmp             ephemeral
all other paths  ephemeral guest image
```

No persistent general home directory is required in the MVP. Durable projects, private skills, and later memory/index data are separate areas of one user-owned storage allocation. Build caches and installed system packages disappear when the sandbox is recycled.

---

## 10. Workspace concurrency and storage

Each user has one durable storage allocation, but an active sandbox receives only the selected project/subdirectory as `/workspace`. It does not automatically receive the user's entire storage namespace.

The daemon/storage layer grants an exclusive writer lease per selected workspace root:

- two sessions cannot mount the same project read/write concurrently;
- sessions for different projects may run concurrently;
- later read-only or Git-worktree modes can relax this deliberately;
- Cogs reports the workspace identity but does not implement the distributed lease.

StorageClass selection is platform-specific:

- AWS reference workspaces: reattachable block storage such as EBS, preferably one volume per project/workspace, because Git metadata and compilation perform poorly on latency-sensitive shared filesystems;
- AWS trusted session state, shared skills, and sharing data: EFS/RWX or object-backed storage where appropriate;
- Hetzner cloud-VM profile: reattachable Hetzner volume or an external filesystem;
- generic Kubernetes: operator-selected CSI storage with a block-storage preference for active workspaces;
- local development: local-path storage with no HA claim.

One user-visible durable namespace may therefore map to multiple project volumes; this is an implementation detail hidden by the workspace service. The storage contract—not a particular CSI vendor—is portable. Workspace writes persist continuously. Guest rootfs and `/tmp` do not.

---

## 11. Secret-injected egress

### 11.1 Placement

A trusted explicit egress proxy runs with the Cogs resource, outside the sandbox VM. Envoy is the initial candidate, not a foregone implementation choice. No proxy sidecar, OpenBao agent, SDS socket, real credential, or CA private key is placed in the sandbox.

The sandbox is configured with:

- `HTTP_PROXY` and `HTTPS_PROXY` pointing to its assigned proxy by literal address or provisioned `/etc/hosts` name;
- a high-entropy, short-lived per-session `Proxy-Authorization` capability;
- non-secret placeholder environment variables for SDK preflight checks;
- the public platform egress CA in system/runtime trust stores;
- no direct Internet route and, by default, no general DNS route.

Host CNI policy or a provider firewall permits only the assigned SSH and proxy paths. Port-scoped policy permits the sandbox to reach the proxy listener but not the Cogs API or proxy administration port even when they share a Pod. The proxy capability is bound to the same session/source policy and stripped before upstream forwarding. Guest root can read and use this capability, but it grants only that session's already-approved routes and is not an upstream credential.

Ignoring proxy environment variables causes connection failure rather than bypass. Some clients resolve target hosts before issuing CONNECT even when configured with a proxy. Phase 0 tests the required Java, Python, Node, Git, and package-manager clients. If compatibility requires DNS, the deployment adds an external resolver that answers only exact allowlisted A/AAAA names and rejects arbitrary names, subdomains, and other query types; unrestricted DNS is not enabled.

### 11.2 MVP proxy construction

The allowlist is immutable for a session, so the MVP avoids a custom xDS control plane:

1. Cogs authenticates to OpenBao using a session-scoped workload identity.
2. It resolves the model credential and approved integration secret handles.
3. It asks OpenBao PKI for a proxy leaf certificate whose SANs are exactly the allowed destination hosts. Its validity exceeds the eight-hour maximum session lifetime plus startup and drain margin; the CA private key never leaves OpenBao.
4. It renders immutable proxy configuration into trusted tmpfs.
5. Static routes encode integration rule groups and header overwrite behavior.
6. The selected proxy starts only after configuration validation succeeds.
7. The integration UI/service sends revocation events to the daemon for immediate drain and replacement.
8. As a backstop, Cogs polls the OpenBao secret version/deletion/lease metadata at a configured interval no greater than 60 seconds. A change marks egress unready, denies new requests, drains existing connections, and requests worker replacement.

Secret values may appear in trusted tmpfs and proxy memory, but never in Kubernetes manifests, logs, the sandbox, or durable session storage. Proxy administration and config-dump interfaces are disabled or bound to a worker-private Unix socket.

This intentionally favors immutable process replacement over live xDS/SDS machinery.

### 11.3 Request checks

For every request the proxy must:

- validate the per-session proxy capability and its externally enforced source binding;
- match a declared integration rule, destination, and port;
- validate CONNECT authority, TLS SNI, HTTP `Host`, and HTTP/2 `:authority` consistency;
- resolve and dial the registered hostname, never a guest-selected destination IP;
- match the declared method and path prefix;
- reject nested CONNECT, upgrades, WebSockets, and DNS-over-HTTPS routes;
- strip guest-supplied authentication headers;
- inject the configured real header value;
- reject missing/revoked secrets rather than forward anonymously;
- validate upstream TLS normally;
- emit an audit record without query strings, request bodies, or credential values.

Queries are omitted or redacted because they frequently contain sensitive data. Path logging is configurable; the default records a matched route name and a redacted path template rather than arbitrary path text.

### 11.4 Audit fail-closed behavior

Before the proxy authorizes credential use, a synchronous local authorization call records a non-secret audit intent in a trusted append-only WAL. The Envoy candidate uses `ext_authz` with `failure_mode_allow: false`; another proxy must provide equivalent fail-closed behavior.

- inability to authorize or append the secret-use record denies the request;
- completion status is added by the proxy's structured access logging;
- WAL-to-OTLP delivery is asynchronous and buffered;
- an unavailable OTLP collector does not stop execution;
- an unwritable/full local audit WAL does stop credentialed egress.

### 11.5 Supported compatibility classes

| Class | MVP |
|---|---|
| HTTP/1.1 bearer header | Supported |
| HTTP/1.1 API-key header | Supported |
| HTTP/1.1 Basic auth | Supported |
| HTTP/2 header injection | Supported and tested |
| HTTPS Git | Supported when destination/method/path policy permits |
| Selected HTTP(S) package registries | Supported |
| General gRPC metadata/streaming | Deferred pending explicit compatibility tests |
| OAuth token lifecycle for sandbox integrations | Deferred; pre-existing bearer access tokens can be injected |
| SigV4/HMAC | Blocked |
| mTLS upstream | Blocked |
| SSH/Git-over-SSH | Blocked |
| Databases and arbitrary TCP | Blocked |
| WebSockets | Blocked |
| QUIC/HTTP/3 and other UDP | Blocked |
| Certificate-pinned clients | Fail closed |

A pre-implementation conformance gate must prove explicit CONNECT termination, inner TLS interception, HTTP/2 behavior, certificate handling, placeholder overwrite, route enforcement, client attribution, and fail-closed auditing. It evaluates the pinned Envoy candidate and at least one established forward-MITM alternative such as mitmproxy or an appropriate Squid configuration against the same tests. A custom Go proxy is a last resort, not presumed to be a safe 500-line implementation. The selected proxy may change; the external trust boundary and conformance contract do not.

---

## 12. Model authentication

Model traffic originates in the trusted Cogs worker and does not traverse the untrusted sandbox proxy.

Two storage paths are used:

1. **Organization and user API keys**
   - stored in OpenBao;
   - resolved by a scoped worker identity;
   - supplied to Pi through `AuthStorage.setRuntimeApiKey()`;
   - held in memory only.

2. **OpenAI/Anthropic subscription OAuth**
   - login UX belongs to the future daemon;
   - a single trusted model-credential broker, owned by the daemon/platform rather than Cogs, owns each user/provider OAuth record and rotating refresh token;
   - the broker serializes refresh and stores the record encrypted in OpenBao;
   - concurrent workers receive short-lived, Pi-compatible access material and never independently hydrate, refresh, or write back a shared refresh token;
   - broker failure fails model authentication closed without invalidating the stored refresh state.

The initial release is API-key-only by default. Subscription authentication is enabled only when the external broker exists, concurrent refresh/revocation tests pass, and the provider permits the intended server-hosted, multi-session deployment model. Otherwise it remains disabled and absent from the advertised support matrix. Technical compatibility is not treated as permission under provider terms.

Compatibility follows the pinned Pi release. Continuously tested support is limited to:

- Anthropic API and, where provider terms permit, subscription authentication;
- OpenAI API and, where provider terms permit, subscription authentication;
- OpenRouter API key authentication.

Administrators can restrict the provider/model list per deployment or launch document.

---

## 13. Skills and context

### 13.1 Shared skills

- published as a versioned, immutable OCI artifact pinned by digest;
- revision supplied in the launch document;
- fetched and verified by a trusted materializer; registry credentials never enter the guest;
- loaded into Pi directly from that trusted artifact, never read back through SFTP or the guest;
- the exact verified payload is transferred into the guest and exposed read-only at `/shared/skills` where the runtime supports an external read-only mount;
- visible to all users;
- never executed in the trusted worker.

Guest root may alter its own view, but cannot change the skill text already loaded into Pi or the revision recorded in the transcript.

### 13.2 User skills

- stored in a user-scoped area unavailable to other users;
- snapshotted into a content-addressed archive in S3-compatible object storage;
- fetched and verified by a trusted materializer without giving object-store credentials to the guest;
- loaded into Pi from the trusted snapshot, then transferred into the guest with the same digest and exposed at `/user/skills`;
- treated as untrusted instructions regardless of storage provenance;
- any scripts run only through sandbox tools.

Skill updates become visible on the next session/resource start in the MVP. Live mutation is avoided because it makes prompts and audits irreproducible.

### 13.3 Project context

Cogs may retrieve `AGENTS.md` and equivalent approved context files through SFTP and pass them as text to Pi. It does not use Pi's default host-filesystem discovery. Missing or malformed context is non-fatal and observable.

---

## 14. Session persistence and export

### 14.1 Authoritative active state

Pi JSONL is written unchanged to trusted per-user/session storage. The sandbox cannot mount or edit it. Cogs-specific metadata lives beside it, not inside the repository.

The active filesystem is authoritative while a worker exists. On graceful shutdown Cogs produces an immutable bundle for the daemon/platform to store in S3-compatible object storage if configured. Cogs itself does not include a cloud-specific object-storage client.

There is no promise of object-storage recovery after every turn. A surviving persistent volume will generally contain newer JSONL, but the declared object backup recovery point is graceful shutdown. Default retention is 30 days.

Deletion removes active state and object copies, including versions where the backend allows it, unless an administrator has configured and disclosed a legal hold or separate retention requirement.

### 14.2 Export bundle

```text
cogs-session-<id>/
  session.jsonl          # Pi-compatible transcript
  manifest.json          # format/Pi versions, hashes, timestamps, model metadata
  git-map.json           # commit/checkpoint to session-entry mappings
  skills.json            # shared and user skill revision identifiers
  attachments/           # omitted by default; explicit inclusion only
```

Raw export is available only through the authenticated API after explicit user action. It is not exposed as a model-callable tool. The response is marked sensitive so the daemon can display a warning. A Pi-compatible renderer can display `session.jsonl`; storage and share-link ACLs belong to the daemon/platform.

### 14.3 Future sanitization hook

Export is implemented as a deterministic pipeline over a copied bundle. A later sanitizer can transform records without changing the authoritative JSONL. The first sanitizer targets credentials/placeholders, usernames, images, and attachments and is explicitly best-effort. It emits a report of removed/replaced fields and never silently labels output as guaranteed anonymous.

---

## 15. Git-to-chat synchronization

The MVP links code history to chat state; it does not automatically restore a workspace.

### 15.1 Mapping record

```json
{
  "repo": "opaque-repository-id",
  "commit": "<sha>",
  "session": "<session-id>",
  "entry": "<pi-entry-id>",
  "turn": 17,
  "observed_at": "...",
  "confidence": "exact|inferred-ancestor|checkpoint",
  "checkpoint_ref": "refs/cogs/sessions/<session>/<turn>"
}
```

The mapping manifest is stored in trusted session storage so the guest cannot later rewrite the record. Git operations and repository observations themselves run inside the untrusted sandbox over SSH; therefore the manifest is a trusted record of an untrusted repository observation, not an attestation that the guest reported an honest tree or commit. Cogs authoritatively supplies only the Pi entry ID, turn, and observation time. A non-secret pointer is also written as a Git note under `refs/notes/cogs` when possible. Cogs never automatically pushes that notes ref; organizations may configure Git transport separately.

### 15.2 Exact mappings

Cogs samples repository `HEAD` by running Git through the sandbox SSH connection:

- before a turn;
- after each completed tool-result message;
- when the run settles;
- during graceful shutdown.

When the sandbox reports that `HEAD` changed, Cogs associates that observed SHA with the latest completed Pi session entry. Here, `exact` means the SHA was observed at that precise Pi boundary; it does not elevate guest-reported Git state into a trusted attestation. This captures commits created by the agent during a turn without modifying the user's branch.

### 15.3 Hidden turn checkpoint

When a run settles, Cogs may invoke Git through SSH with a temporary index and `git commit-tree` to snapshot tracked and non-ignored workspace state under:

```text
refs/cogs/sessions/<session-id>/<turn>
```

This does not modify `HEAD` or the user's index. Dirty human changes present when the prompt began are included in the next checkpoint, as requested. Configured exclusions, `.gitignore`, changed-file limits, file-size limits, total checkpoint-size limits, and a checkpoint timeout apply. Phase 0/3 benchmarks checkpoint latency on large dirty repositories; deployments may disable hidden snapshots while retaining actual-commit mappings. Checkpoints are local unless a platform explicitly transports them.

### 15.4 Existing and unmapped commits

For a requested commit:

1. return an exact mapping if one exists;
2. otherwise find the nearest mapped ancestor and label it inferred;
3. explain the gap and offer that earlier chat state;
4. if no mapping exists, report that the commit predates or occurred outside Cogs tracking.

Historical brownfield commits are not fabricated into exact mappings. Human commits made while no worker is active can only be associated with the latest previously known chat state and are marked inferred.

### 15.5 Future restoration

The policy action and resolver response for restoration are reserved now. A later chat restore creates a new Pi session fork at the mapped entry; it never truncates or mutates the original JSONL. Workspace restoration will require a clean workspace or explicit approval and is not part of the MVP.

MVP Git support is one repository root. Non-Git workspaces retain chat but make no code-state promise. Submodules, multi-repository workspaces, and special Git LFS restoration semantics are deferred.

---

## 16. Observability and audit

### 16.1 OpenTelemetry

Cogs emits OTLP without depending on a particular backend. Trace context supplied by the daemon propagates through the worker and is correlated with proxy and platform resource telemetry.

Recommended spans:

- session startup/shutdown;
- Pi turn and model call;
- tool dispatch and SSH/SFTP operation;
- egress authorization and upstream request;
- Git observation/checkpoint;
- export;
- credential resolution by handle, never value.

Recommended metrics:

- input/output/cache tokens and reported cost;
- turn and model latency;
- active/idle session state;
- tool count, latency, errors, timeouts, and output truncation;
- egress request count, status, bytes, and latency by integration/route;
- VM CPU, memory, disk, and network from Kubernetes/node collectors;
- startup and sandbox-ready latency;
- checkpoint/export failures;
- audit WAL depth and OTLP export lag.

### 16.2 Privacy defaults

Central telemetry contains opaque user/session/workspace identifiers and operational metadata. It does not contain:

- prompts or model output;
- source text;
- complete shell commands;
- arbitrary file paths;
- tool output;
- HTTP query strings or bodies;
- credentials or placeholders.

Exact commands, paths, and tool results remain in the user-owned Pi transcript. Enterprises may opt into a separately protected command-audit sink with explicit retention and access controls, but it is disabled by default.

### 16.3 MVP execution and filesystem audit

The MVP records:

- Pi tool invocation metadata;
- explicit `read`, `write`, and `edit` operations;
- bash start/end, exit status, duration, and transcript reference;
- Git diffs/checkpoints;
- authoritative network/credential-use audit;
- platform resource telemetry.

It does not claim to record every file read by a shell process or every guest syscall. Authoritative filesystem auditing would require an external mediated filesystem or equivalent host instrumentation and is deferred.

---

## 17. Policy

Cogs has one versioned action envelope and one authorization function. The MVP implementation is static and in-process; a later implementation may call OPA using the same envelope.

```json
{
  "version": "cogs.policy/v1alpha1",
  "action": "tool.dispatch",
  "user": "opaque-user-id",
  "session": "opaque-session-id",
  "resource": "bash",
  "attributes": {}
}
```

MVP decision points are:

- validating mounts and immutable launch capabilities;
- enabling a Pi tool;
- dispatching a tool;
- authorizing destination/method/path and secret use;
- selecting raw or sanitized export;
- reserved restore action.

Session admission, worker count, cross-session quota, workspace leases, and app approval belong to the daemon/platform. Shell text is not interpreted as a security policy; `bash` receives a general sandbox capability.

Policy decisions and tool wrappers are insignificant compared with model and process latency. They are not expected to be a performance concern.

---

## 18. Resource lifecycle and scale

Initial defaults:

| Class | CPU | Memory |
|---|---:|---:|
| Default | 2 vCPU | 4 GiB |
| Large | 4 vCPU | 8 GiB |
| Maximum | 8 vCPU | 16 GiB |

Additional defaults:

- 20 GiB ephemeral guest disk;
- 30-minute idle shutdown;
- eight-hour maximum sandbox lifetime before recycle, with normal recycle requested at a settled turn boundary and a separately configured emergency hard deadline;
- four concurrent sessions per user by default, administratively configurable;
- under-30-second cold start on the accelerated Kata profile;
- stopped sessions release CPU and memory while retaining workspace and session state.

At 250 default-sized active sessions, requested capacity is 500 vCPU and 1 TiB RAM before trusted-worker and system overhead. The platform therefore requires autoscaled dedicated node pools and enforced admission quotas; this is not a small static cluster.

Sub-five-second startup is a future optimization using pre-pulled images and a bounded warm pool. It must not weaken isolation by reusing dirty guest state between users. Warm instances are reset from an immutable image and receive fresh identities, mounts, proxy configuration, and host keys.

---

## 19. NIC and Helm integration

Cogs is delivered as a standalone Helm chart suitable for a NIC Software Pack and generic Kubernetes. The pack installs long-lived prerequisites and templates; the external daemon later creates per-session resources.

### 19.1 Pack responsibilities

- Cogs namespace, service accounts, roles, and NetworkPolicies;
- trusted worker and sandbox Pod templates;
- Kata `RuntimeClass` reference and install-time validation;
- dedicated node selectors and tolerations;
- shared-skill OCI artifact and trusted materializer configuration;
- private-skill S3-compatible artifact/materializer configuration;
- OpenBao Kubernetes-auth role and least-privilege policy templates;
- public egress CA distribution;
- OTLP endpoint configuration;
- workspace/session StorageClass settings;
- resource defaults and limits;
- optional `NebariApp` registration for platform discovery, without exposing a user UI.

### 19.2 NIC changes

The AWS reference deployment needs a declarative sandbox node-group option using NIC's existing node-group labels, taints, scaling, and storage support. NIC must be able to express and preserve a custom launch-template ID/version containing `CpuOptions.NestedVirtualization=enabled`; if its node-group abstraction cannot, NIC must be extended before EKS validation. Active Git/build workspaces should default to reattachable block volumes; EFS remains useful for trusted session state and shared artifacts. NIC remains responsible for infrastructure reconciliation; Cogs does not call cloud APIs.

Because runtime installation is cluster-scoped, validation must fail clearly when:

- the instance type/region is unsupported, the rendered launch template does not enable nested virtualization, required AMI KVM modules are absent, or no KVM-capable node is available;
- the requested `RuntimeClass` is absent;
- the CNI cannot enforce NetworkPolicy for Kata pods;
- required volume modes are unsupported;
- IPv6/UDP/default-deny tests fail;
- OpenBao or OTLP configuration is invalid.

No end-to-end production claim is made for NIC providers that are currently stubs or incomplete.

---

## 20. Future interfaces

### 20.1 Search and indexing

Every settled turn emits `workspace_revision` with repository SHA/checkpoint, changed-file summary, and session entry. A later indexer can consume this event and scan the durable workspace out of band. No vector database client enters Cogs MVP.

### 20.2 Apps and approvals

A future app broker is a typed external tool. It receives no Kubernetes credential from Cogs or the sandbox. Below configured resource quota it may approve automatically; above quota it returns an immutable pending action.

Future approval flow:

1. Cogs emits `approval_required` with action and idempotency key.
2. The tool returns a pending result and the Pi run settles.
3. The daemon obtains approval.
4. The daemon sends a new follow-up referencing the approved action.

Cogs does not durably suspend a process or tool call.

### 20.3 External app diagnostics

When apps exist, logs/metrics/traces are exposed through bounded broker operations returning summaries and artifact references. The agent never receives Kubernetes, Loki, Tempo, Prometheus, or cloud credentials.

### 20.4 Additional egress classes

OAuth lifecycle, SigV4/HMAC signing, mTLS, gRPC, and protocol-specific proxies are separate implementations with separate tests and policy schema. They are not generic flags on the bearer-header mechanism.

---

## 21. Failure behavior

| Failure | Behavior |
|---|---|
| Sandbox unavailable | Worker remains unready; tool call fails without local fallback |
| SSH host key mismatch | Fail closed; never accept a changed key automatically |
| Proxy unavailable | Sandbox has no egress |
| OpenBao unavailable at startup | Worker remains unready |
| Secret missing/revoked or metadata version changes | New requests denied; connections drained; daemon replaces worker/proxy within the declared revocation bound |
| OAuth broker unavailable | Subscription authentication is unavailable and fails closed; API-key authentication is unaffected |
| Audit authorization/WAL failure | Credentialed request denied |
| OTLP unavailable | Buffer within limits, then drop with counters; agent continues |
| Session storage unavailable | Stop accepting prompts to avoid transcript divergence |
| Object backup failure | Report shutdown warning; retained filesystem remains authoritative |
| Git not present/non-repository | Continue session without Git mapping |
| Git mapping failure | Report warning; never fail the completed agent turn |
| Tool timeout/output overflow | Terminate/truncate and return explicit status to Pi |
| Eight-hour recycle reached | Drain at the next settled turn; use the emergency hard deadline only when draining cannot complete |
| Worker termination | Kubernetes restarts only if daemon still owns the session; no implicit prompt replay |

---

## 22. Minimal implementation shape

The implementation should remain a small TypeScript service around Pi:

```text
src/
  main.ts             launch validation and lifecycle
  api.ts              HTTP/SSE protocol
  pi-session.ts       Pi SDK construction and event forwarding
  tools.ts            read/write/edit/bash definitions
  ssh.ts              SSH/SFTP transport
  policy.ts           action envelope and static authorization
  git-map.ts          commit observation and checkpoint mapping
  export.ts           Pi-compatible bundle creation
  egress.ts           immutable proxy config and local authorization/audit WAL
  telemetry.ts        OpenTelemetry wiring
  auth.ts             OpenBao API-key and model-broker client
```

The guest image adds configuration, not an agent framework:

- Ubuntu or Debian base;
- OpenSSH server;
- CA public certificate and trust-store environment variables;
- standard development tools selected by the platform image;
- no Cogs-specific privileged daemon.

Targets, excluding tests, generated schemas, Helm templates, and vendored dependencies:

- Cogs worker planning target: approximately 3,000–5,000 production lines;
- no custom database;
- no custom Kubernetes controller in the Cogs repository;
- no generic plugin framework;
- no provider abstraction beyond the SSH/proxy contract already required at the trust boundary.

Crossing 5,000 production lines triggers a scope and architecture review rather than pressure to compress security-sensitive code. Features should be removed or delegated rather than absorbed into a monolith. A post-MVP hardening option moves integration-secret hydration and proxy-bootstrap rendering into a small separate trusted process/resource, reducing the credentials reachable by a parsing bug in the Pi event path.

---

## 23. Implementation phases

### Phase 0 — local feasibility and executable security contract

Begin with a short Pi embedding spike. It must prove headless `createAgentSession()`, exactly four custom stub tools, disabled extension/package discovery using hostile canaries, fake-model tool execution, runtime API-key injection, and native JSONL round-trip through the pinned Pi CLI/library. A failure changes the design before sandbox work begins.

The first security artifact is a standalone applicability-aware egress conformance suite. `Stubbed` results may select a mechanism but never satisfy release acceptance. Run inexpensive protocol tests in the insecure container on PRs and authoritative guest-root bypass tests on a maintained Linux/KVM runner nightly and for security-labelled changes.

1. Run CONNECT-MITM, HTTP/1.1/HTTP/2, certificate, header-overwrite, route-group, request-smuggling, and client-compatibility tests against Envoy and at least one established proxy alternative.
2. Prove guest root on Linux/KVM cannot bypass egress using direct IP, alternate TCP ports, IPv6, UDP/QUIC, DNS, altered proxy variables, forged Host headers, or access to the worker API port.
3. Test required Java, Python, Node, Git, PyPI, and npm clients; add allowlist-only DNS only if a required client resolves before CONNECT.
4. Use stub authorization/audit/revocation dependencies for early proxy selection, then replace every mandatory stubbed result with real Cogs/OpenBao results during integration.
5. After local proxy selection, run a short single-EC2 campaign using a launch template with `CpuOptions.NestedVirtualization=enabled`; verify region support, AMI KVM modules, Kata compatibility, performance, and cost before creating EKS.
6. Prove OpenBao PKI leaf issuance, proxy-certificate lifetime, secret retrieval, version polling, and revocation draining without durable leakage.
7. Measure Kata cold start, SSH readiness, and hidden-checkpoint cost on large dirty repositories.

A failed spike changes the selected mechanism before production code is built; it does not weaken the security contract.

### Phase 1 — core worker

- launch schema;
- Pi SDK session;
- internal HTTP/SSE API, paged history, and bounded duplicate-request suppression;
- SSH/SFTP tools;
- JSONL persistence;
- static policy and OTLP;
- no egress credentials yet.

### Phase 2 — secure egress

- OpenBao API-key hydration and model-credential broker client;
- immutable route-group generation for the proxy selected by conformance testing;
- explicit proxy, per-session proxy capability, port isolation, and trust stores;
- ext-auth audit WAL;
- tested GitHub/PyPI/npm presets;
- destination/method/path tests;
- immediate revocation signal, OpenBao metadata polling, connection drain, and resource replacement.

### Phase 3 — workspace, skills, and Git

- persistent workspace contract;
- shared/private skill loading;
- commit observation, notes, manifest, and hidden refs;
- exact/inferred lookup.

### Phase 4 — export and packaging

- portable bundles;
- shutdown backup handoff;
- Helm/NIC Software Pack;
- EKS load and security testing;
- operator documentation.

### Phase 5 — portability

- Hetzner Cloud full-VM provisioner integration with warm pool;
- Hetzner dedicated/k3s Kata validation;
- GCP, Azure, and local Linux validation;
- best-effort sanitizer and later feature hooks.

---

## 24. Acceptance criteria

The MVP is not complete until automated tests demonstrate:

1. standard Pi JSONL can be opened by the pinned Pi CLI/library;
2. no built-in host tool, project extension, or project package executes in Cogs, including hostile discovery canaries;
3. all four tools operate only through SSH/SFTP;
4. guest root cannot read worker files, session JSONL, model credentials, integration credentials, OpenBao identity, or CA private keys;
5. guest root cannot reach an undeclared destination by hostname, IP, IPv6, DNS tunnel, UDP, alternate port, CONNECT tunnel, or proxy bypass;
6. auth headers supplied by the guest are stripped/overwritten;
7. method and path restrictions deny disallowed requests;
8. SNI/Host/authority mismatch is denied;
9. ambiguous HTTP requests and request-smuggling/desynchronization probes are rejected before they can bypass route or credential policy;
10. audit authorization failure denies secret use while OTLP outage does not stop ordinary work;
11. revocation prevents new requests, drains existing proxy connections, and is detected within the declared bound even after a direct OpenBao change;
12. the sandbox can reach its proxy listener but not the Cogs API/admin ports, and a wrong proxy capability is denied;
13. history can be rebuilt through paged entries after SSE replay-buffer eviction;
14. if subscription OAuth is enabled, concurrent sessions cannot race or overwrite a rotating refresh token; otherwise subscription OAuth is disabled and not advertised;
15. a Git commit created during a turn resolves to the correct completed Pi entry and is labeled as a sandbox observation;
16. an unmapped historical commit produces the documented nearest-ancestor fallback;
17. hidden checkpoints do not modify `HEAD` or the user index and obey size/time limits;
18. raw export requires the authenticated non-tool API and produces a valid, hashed bundle;
19. private skills cannot cross user boundaries, and the prompt and guest copy use the recorded skill-artifact digest;
20. CPU, memory, disk, timeout, output, and session-lifetime limits are enforced externally to guest root;
21. accelerated cold start is under 30 seconds at the agreed load percentile;
22. central telemetry at the highest validated real concurrency contains no prompts or source; the advertised concurrency maximum does not exceed that validated load.

---

## 25. Key decisions and rejected alternatives

| Decision | Reason |
|---|---|
| Embed Pi SDK | Preserves Pi behavior and avoids rebuilding an agent framework |
| One Cogs worker per active Pi session | Simple ownership and failure isolation |
| Lifecycle in external daemon | Keeps cloud/Kubernetes credentials and scheduling out of Cogs |
| SSH/SFTP sandbox contract | Established, portable, and eliminates a custom guest daemon |
| Kata Pod for reference runtime | VM boundary with normal Kubernetes lifecycle |
| Full cloud VM for Hetzner Cloud | Avoids unsupported nested virtualization and unusable production emulation |
| Proxy outside sandbox | Guest root would compromise an in-VM proxy and its credentials |
| Explicit proxy plus external default deny | Simpler than universal transparent TPROXY while remaining non-bypassable |
| Immutable per-session proxy config and worker replacement | Avoids an MVP xDS/SDS control plane; proxy implementation is chosen by conformance tests |
| OpenBao reference secret store | Scoped identity, revocation, PKI, and encrypted credential storage |
| Native Pi JSONL | Interoperability and minimal code |
| Manifest plus Git notes | Trusted preservation of explicitly untrusted sandbox observations with repository-local discoverability |
| No automatic notes push | Avoids surprising remote-repository mutation |
| Metadata-only central telemetry | Enterprise observability without centralizing source/prompts by default |
| Static in-process policy first | Preserves an OPA boundary without adding a policy service |
| No authoritative filesystem audit | It would reintroduce filesystem mediation not required for MVP |
| No general gRPC claim | HTTP/2 support alone does not validate streaming/trailer/revocation semantics |
| No custom session database | Pi JSONL plus filesystem/object export is sufficient |

---

## 26. Residual risks to state publicly

- A malicious agent can misuse every capability it is intentionally granted.
- An approved write-capable endpoint can be used to exfiltrate source; there is no DLP.
- The model provider receives prompt content and selected source by design.
- TLS interception breaks pinned/custom trust clients and those clients fail closed.
- Hypervisor and QEMU/Kata vulnerabilities remain part of the trusted computing base.
- A compromised trusted Cogs worker can access that session's model and integration credentials; separating proxy bootstrap is deferred hardening.
- Guest root can copy its short-lived proxy capability, although external source binding and route policy limit it to the same session capability.
- Subscription OAuth remains conditional on provider terms and a single-owner refresh broker.
- Git mappings preserve what the untrusted sandbox reported; they do not attest repository integrity.
- Human commits made while Cogs is absent cannot be mapped to an exact chat moment.
- Object-store backup occurs only on graceful shutdown in the initial policy.
- Operational filesystem audit does not reveal every guest file access.
- The under-30-second Hetzner Cloud target requires a warm pool and must be validated separately.

These are design boundaries, not implementation defects, and must not be obscured in product claims.
