# Cogs Implementation Plan

**Status:** Proposed execution plan  
**Date:** 2026-07-09  
**Audience:** Staff engineer and implementation team  
**Target:** Complete local development, AWS feasibility, EKS/NIC integration, and pre-release validation through Stage 5.

`DESIGN.md` is the architectural and security authority. This document defines execution order, artifacts, gates, and evidence. If implementation requires changing a security invariant or trust boundary, stop and record an ADR before proceeding.

Previous Nebula designs and earlier Nebari Pi packs may be studied as prior art but are not requirements or implementation baselines.

---

## 1. Delivery principles

1. **Local-first, not local-only.** Most development happens locally. AWS is used for short, explicit validation campaigns.
2. **Executable security contract first.** Build the egress conformance suite before building the complete agent.
3. **No insecure fallback.** Development drivers are clearly labelled. Production readiness requires a passing VM-backed profile.
4. **Keep Cogs small.** Do not add daemon responsibilities, a workflow engine, a database, or a Kubernetes controller to Cogs.
5. **Use the same boundaries everywhere.** Local container, local VM, Kata, and Hetzner profiles all use the same SSH/SFTP, proxy, and Cogs APIs.
6. **Choose mechanisms through evidence.** Proxy and AWS runtime choices remain provisional until their gates pass.
7. **Fail closed.** Missing policy, audit, identity, secret, proxy, or sandbox dependencies must not degrade to local execution or open egress.
8. **Preserve Pi.** Use the current pinned `@earendil-works/*` SDK and native Pi JSONL rather than wrapping its core behavior.
9. **No production claim without evidence.** Each security claim must point to a repeatable test result.
10. **Destroy cloud environments by default.** AWS test resources are ephemeral and TTL-labelled.

---

## 2. Scope through Stage 5

### Included

- Pi SDK worker with one active Pi session per worker;
- internal HTTP/SSE/history API;
- bounded duplicate-request suppression;
- SSH/SFTP-backed `read`, `write`, `edit`, and `bash`;
- insecure local container driver;
- VM-backed local driver;
- Kata reference profile on AWS EKS;
- external full-VM-compatible SSH/proxy contract;
- explicit HTTP/HTTPS proxy with external default-deny;
- bearer, API-key header, and Basic auth injection;
- host/method/path rule groups and tested presets;
- OpenBao API-key storage and PKI;
- model API-key support and an external OAuth broker client contract;
- persistent Pi JSONL;
- paged history and raw export;
- content-addressed shared and private skills;
- Git-to-chat observation, notes, and bounded hidden checkpoints;
- static policy envelope and future OPA boundary;
- OpenTelemetry and fail-closed credential-use audit;
- Helm/NIC packaging;
- security, failure, scale, and cost validation.

### Excluded

- production daemon implementation;
- UI and user-facing ingress;
- arbitrary attachments transport;
- apps and approval execution;
- session sanitization implementation;
- indexing/vector search;
- full workspace or chat restoration;
- authoritative filesystem/syscall audit;
- gRPC injection claims;
- SigV4, HMAC, mTLS, databases, SSH egress, WebSockets, or arbitrary TCP;
- GCP/Azure production validation;
- production Hetzner provisioner implementation unless separately commissioned.

A development launcher may create resources and drive Cogs. It must not evolve into an accidental daemon.

---

## 3. Proposed repository layout

```text
.
├── DESIGN.md
├── IMPLEMENTATION.md
├── docs/
│   ├── adr/
│   ├── operations/
│   ├── security-evidence/
│   └── test-reports/
├── src/
│   ├── main.ts
│   ├── api.ts
│   ├── config.ts
│   ├── pi-session.ts
│   ├── tools.ts
│   ├── ssh.ts
│   ├── policy.ts
│   ├── git-map.ts
│   ├── export.ts
│   ├── egress.ts
│   ├── auth.ts
│   └── telemetry.ts
├── schemas/
│   ├── launch-v1alpha1.json
│   ├── events-v1alpha1.json
│   ├── policy-v1alpha1.json
│   ├── integration-v1alpha1.json
│   ├── export-manifest-v1alpha1.json
│   └── git-mapping-v1alpha1.json
├── test/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   ├── egress-conformance/
│   │   ├── controller/
│   │   ├── guest-probes/
│   │   ├── upstream-fixtures/
│   │   ├── proxy-adapters/
│   │   └── reports/
│   ├── load/
│   └── fixtures/
├── dev/
│   ├── compose/
│   ├── insecure-sandbox/
│   ├── macos-vm-dev/
│   ├── linux-kvm/
│   ├── fake-model-broker/
│   └── launcher/
├── images/
│   ├── worker/
│   └── sandbox/
├── deploy/
│   ├── helm/cogs/
│   ├── local/
│   └── aws-feasibility/
├── integrations/
│   ├── github-clone.yaml
│   ├── pypi-install.yaml
│   └── npm-install.yaml
├── package.json
├── package-lock.json
└── tsconfig.json
```

Do not add a production `controller/`, `gateway/`, or provider SDK package to this repository without an approved design change.

---

## 4. Technology baseline

The staff engineer should pin exact versions during Stage 0 rather than using floating tags.

### Production code

- Node.js 22 or later supported LTS;
- strict TypeScript;
- current pinned `@earendil-works/*` Pi packages;
- Node's HTTP primitives or one small HTTP dependency;
- an SSH/SFTP library with active maintenance and host-key verification;
- OpenTelemetry SDK and OTLP exporter;
- JSON Schema validation at process startup;
- OpenBao HTTP API using Kubernetes auth in cluster and a development token locally.

### Runtime dependencies

- Ubuntu or Debian sandbox image;
- OpenSSH server;
- Kata Containers with QEMU/KVM for the reference profile;
- proxy selected by Stage 1 conformance testing;
- OpenBao;
- Kubernetes NetworkPolicy-capable CNI;
- CSI block storage for active workspaces;
- OTLP collector.

### Test tooling

The conformance harness may use a language different from Cogs if that materially improves raw-network testing. A practical split is:

- a test controller using pytest or the Node test runner;
- a small static Go guest probe for TCP, UDP, DNS, HTTP/1.1, HTTP/2, and malformed requests;
- real Git, Python/pip, npm, Java, curl, and language SDKs for compatibility tests;
- an upstream fixture server that supports TLS and HTTP/2 and never reflects injected credentials.

Test code is not part of the Cogs line-count budget. Consistent with `DESIGN.md`, implementation planning should expect approximately 3,000–5,000 production lines after history, deduplication, broker, preset, revocation, and proxy-capability work. Crossing 5,000 production lines triggers a scope and architecture ADR rather than pressure to compress security-sensitive code.

---

## 5. Stage overview and gates

| Stage | Primary environment | Outcome | Exit gate |
|---|---|---|---|
| 0 | Local | Repository, schemas, CI, Pi embedding proof, evidence conventions | Reproducible build plus passing Pi hello-world |
| 1 | Local container + authoritative Linux/KVM runner | Executable egress contract and proxy decision | Applicable conformance passes on chosen proxy |
| 2 | Short-lived single AWS instance | AWS nested-KVM/Kata feasibility | Runtime ADR with measured pass/fail |
| 3 | Local + Linux/KVM runner | Complete secure Cogs vertical slice | End-to-end prompt in Linux/KVM sandbox passes |
| 4 | Ephemeral AWS EKS/NIC | Production topology integration | EKS security and cold-start gates pass |
| 5 | Ephemeral AWS EKS plus local CI | Pre-release security, resilience, scale, operations | Signed release-readiness report |

Stage numbering below follows this table. Stage 0 is repository preparation plus the early Pi feasibility spike; Stages 1–5 match the local/AWS progression.

### 5.1 Relative effort and cloud windows

These are planning sizes, not delivery-date commitments:

| Epic | Relative size | Cloud expectation |
|---|---|---|
| Foundation and Pi embedding spike | Small | None |
| Egress conformance and proxy selection | Extra large | None; KVM runner required |
| AWS single-instance feasibility | Small | One short, same-day instance campaign |
| Cogs core | Large | None |
| Auth and secure egress integration | Large | None until EKS validation |
| Sessions, skills, Git, and export | Medium–large | None |
| EKS/NIC integration | Extra large | Time-boxed EKS campaigns, destroyed afterward |
| Release security/load validation | Extra large | Pre-approved campaign windows and spend caps |

Stage 0 must identify the KVM runner and the engineer/approver for each AWS campaign. Calendar estimates should be added only after the Pi and proxy spikes remove the largest unknowns.

---

# Stage 0 — Repository and engineering foundation

## 6. Objectives

- Make builds reproducible.
- Convert the design into versioned schemas and tracked acceptance tests.
- Prevent accidental secret leakage and dependency drift.
- Establish the evidence format used by later security gates.
- Prove the pinned Pi SDK can satisfy the trusted-worker invariants before runtime and proxy work proceeds.
- Select the authoritative Linux/KVM CI or development runner.

## 7. Tasks

### 7.1 Initialize project and CI

- Initialize Git with protected main branch conventions.
- Configure strict TypeScript and deterministic package locking.
- Add formatter/linter, unit-test runner, and type checking.
- Add image build definitions for worker and sandbox.
- Build multi-architecture images where dependencies permit; production AWS validation remains on the selected AWS architecture.
- Add dependency, license, vulnerability, and secret scanning.
- Generate SBOMs for both images.
- Pin base images by digest in release builds.

Minimum CI checks:

```text
format/lint
TypeScript typecheck
unit tests
JSON Schema validation
Helm lint/template
container build
secret scan
vulnerability scan
SBOM generation
```

As the conformance suite becomes available, wire profiles as follows:

| Profile | CI schedule |
|---|---|
| Unit/API/schema/Pi embedding | Every PR |
| `insecure-container` conformance | Every security-relevant PR; target every PR once stable |
| `linux-kvm` conformance | Nightly and on an explicit security label |
| EKS/Kata conformance | Scheduled AWS campaigns and release candidates |
| Full load ramp | Stage 5 only |

Stage 0 must select a self-hosted runner or CI offering that explicitly guarantees KVM. Do not assume hosted-runner `/dev/kvm` behavior without a maintained verification job.

### 7.2 Pi embedding hello-world spike

Time-box this as the first functional spike. It requires no VM, proxy, OpenBao, or AWS.

Implement a disposable headless program that:

- pins and calls `createAgentSession()` from the selected `@earendil-works/*` release;
- constructs `AuthStorage`, `ModelRegistry`, `SessionManager`, and the resource loader explicitly;
- registers exactly four harmless stub tools named `read`, `write`, `edit`, and `bash`;
- uses a fake model/stream function to trigger at least one tool call;
- supplies a custom resource loader with extensions and packages disabled;
- places executable-canary extensions/packages in project and global discovery locations and proves they do not run;
- exercises runtime API-key injection using a non-secret test value;
- writes native JSONL, reloads it, navigates its branch, and opens/round-trips it with the pinned Pi CLI/library;
- records the exact Pi APIs relied upon and any unsupported assumptions.

If extension/package discovery cannot be disabled or replaced cleanly, stop and amend `DESIGN.md` before proceeding. Move reusable spike code into Stage 3 only after the gate passes.

### 7.3 Define versioned contracts

Create schemas for:

- launch configuration;
- integration rule groups;
- event envelope;
- policy action envelope;
- session-export manifest;
- Git mapping record.

Contract rules:

- reject unknown security-sensitive fields by default;
- use opaque identifiers rather than usernames in runtime records;
- never permit inline real integration credentials;
- represent secrets through handles;
- require immutable integration and skill revisions;
- require explicit protocol versions.

### 7.4 Establish ADRs

Create initial ADRs for:

1. Pi SDK embedding and extension disabling;
2. SSH/SFTP as the sandbox protocol;
3. external proxy plus default-deny;
4. Kata reference runtime and full-VM compatibility profile;
5. native Pi JSONL;
6. trusted recording of untrusted Git observations;
7. single-owner OAuth refresh broker;
8. metadata-only central telemetry;
9. skill artifact distribution.

The skill artifact ADR should select this reference unless implementation evidence requires another mechanism:

- shared skills are immutable OCI artifacts pinned by digest;
- private skills are content-addressed archives in S3-compatible object storage;
- a trusted materializer fetches and verifies the artifact;
- Cogs loads prompt text from the verified trusted copy and transfers the same archive into the guest over SFTP;
- the guest receives no registry/object-store credential;
- local development uses a filesystem or MinIO while preserving the same digest/manifest contract.

The proxy-selection and AWS-runtime ADRs remain pending until Stages 1 and 2.

### 7.5 Security-evidence format

Every conformance run must produce a machine-readable and human-readable report containing:

- source revision;
- image digests;
- runtime/profile versions;
- test list, conformance group, and result;
- applicability state: `pass`, `fail`, `stubbed`, `not-applicable`, or `skipped-with-approved-reason`;
- the real or stubbed dependency used for authorization, audit, revocation, identity, and network enforcement;
- environment metadata;
- timestamps and duration;
- redacted failure diagnostics;
- known skips and justification.

A `stubbed` result is useful for mechanism selection but can never satisfy production release acceptance. `skipped-with-approved-reason` requires an owner and expiry/review point.

Reports live under `docs/security-evidence/` for release candidates; routine CI artifacts need not be committed.

## 8. Stage 0 exit criteria

- [ ] Clean checkout builds worker and sandbox images.
- [ ] CI enforces lint, typecheck, unit tests, schema validation, and Helm rendering.
- [ ] Pi hello-world proves custom tools, disabled discovery, fake model operation, runtime auth, and JSONL round-trip.
- [ ] A maintained Linux/KVM runner and conformance schedule are selected.
- [ ] No unpinned production image tags remain.
- [ ] Initial ADRs, including skill artifact transport, are reviewed.
- [ ] Security reports have a defined applicability schema.
- [ ] No cloud resources are required for default CI.

---

# Stage 1 — Local egress contract and proxy selection

## 9. Objectives

- Implement the executable security contract before integrating Pi.
- Compare proxy candidates using identical black-box tests.
- Prove proxy protocol behavior first in an insecure container and then prove root-bypass controls on an authoritative Linux/KVM boundary.
- Keep macOS VM tooling optional and explicitly non-authoritative.
- Select the proxy through an ADR.

## 10. Local environments

### 10.1 Insecure development driver

Provide a plain container containing:

- Ubuntu/Debian userland;
- OpenSSH server;
- root access;
- test clients;
- mounted temporary workspace;
- injected public CA and proxy variables.

It uses the production SSH/SFTP and proxy contracts but has **no VM isolation claim**. Every command and report must label the profile `insecure-container`.

### 10.2 macOS VM convenience driver

A UTM, QEMU/HVF, or similar Ubuntu/Debian VM may be provided for developer convenience. It exercises SSH/SFTP, guest-root behavior, workspace disks, and proxy protocol compatibility, but it is not an authoritative default-deny security profile. Do not make Stage 1 or Stage 3 security gates depend on macOS `vmnet`/`pf` behavior, and label its reports `macos-vm-dev`.

### 10.3 Authoritative Linux/KVM driver

Provision an Ubuntu/Debian VM on a KVM-capable Linux workstation, self-hosted runner, or CI service that explicitly guarantees KVM.

Required properties:

- separate guest kernel;
- guest root available;
- host-generated SSH host key injected before boot;
- persistent workspace disk;
- host-controlled isolated network;
- no ordinary guest Internet/NAT path;
- only SSH from the trusted host and proxy access allowed;
- proxy and CA private key remain outside the VM;
- reproducible create, reset, and destroy commands.

Do not rely on the guest firewall for the default-deny claim. Guest root must be able to alter its firewall without gaining another egress path. This `linux-kvm` profile is the only local profile that can satisfy guest-root network-bypass exit criteria.

## 11. Egress conformance architecture

```text
trusted test controller
├─ starts proxy candidate
├─ starts upstream fixtures
├─ controls external firewall/network
├─ submits probes over SSH
├─ controls audit sink health
└─ verifies proxy and upstream records

untrusted guest
├─ knows placeholder credential
├─ knows session proxy capability
├─ has root
└─ attempts allowed and forbidden traffic
```

### 11.1 Upstream fixtures

Provide fixtures for:

- HTTP/1.1 TLS endpoint;
- HTTP/2 TLS endpoint;
- header-protected endpoint;
- Basic-auth endpoint;
- redirect endpoint;
- large/streaming response endpoint;
- delayed connection for drain/revocation tests;
- TCP and UDP listeners used only to prove denial.

The fixture records the received credential as a boolean/hash comparison only. It never returns or logs the real value.

### 11.2 Required conformance groups

#### Identity and route authorization

- correct session proxy capability succeeds;
- missing, malformed, expired, or other-session capability fails;
- allowed host/port succeeds;
- undeclared hostname fails;
- direct destination IP fails;
- alternate TCP port fails;
- wrong method fails;
- wrong path fails;
- encoded/traversal path variants fail unless explicitly normalized and allowed;
- redirect to an undeclared destination fails;
- SNI, CONNECT authority, `Host`, and `:authority` mismatch fails.

#### HTTP parsing and request-smuggling resistance

Send raw and protocol-valid/invalid probes covering:

- conflicting `Content-Length` and `Transfer-Encoding`;
- duplicate `Host`, `Authorization`, and proxy-authorization headers;
- absolute-form versus origin-form request targets;
- ambiguous whitespace and obsolete header folding;
- oversized headers and request lines;
- invalid chunk sizes and chunk extensions;
- encoded slash/dot and path-normalization disagreements;
- duplicate, reordered, or invalid HTTP/2 pseudo-headers;
- HTTP/2-to-HTTP/1 downgrade ambiguity.

The proxy must reject ambiguous input before policy evaluation or normalize it once in a documented way used by routing, authorization, audit, and upstream forwarding. No downstream component may interpret a rejected request differently.

#### Credential handling

- placeholder satisfies client-side SDK preflight;
- guest-supplied authorization is stripped;
- correct real credential arrives upstream;
- real credential never appears in guest output, proxy access log, audit WAL, or OTLP;
- absent/revoked secret returns a clear failure and is not forwarded anonymously;
- Basic and configured API-key headers behave identically to bearer injection.

#### Bypass resistance

From guest root attempt:

- unset proxy variables;
- direct IPv4;
- direct IPv6;
- arbitrary DNS;
- DNS-over-HTTPS;
- UDP/443 and QUIC;
- alternate TCP ports;
- nested CONNECT;
- WebSocket upgrade;
- forged Host/SNI;
- access to Cogs API port;
- access to proxy admin/config endpoint;
- access to OpenBao;
- access to cloud metadata addresses.

All must fail outside explicitly allowed behavior.

#### Audit and failure behavior

Stage 1 runs this group against a fault-injectable stub authorization/audit service. Stage 3 reruns it against the real Cogs WAL and authorization path.

- authorization intent is written before credential use;
- unwritable/full audit WAL causes denial;
- authorization service outage causes denial;
- OTLP outage does not stop an otherwise valid uncredentialed operation;
- completion status and latency correlate with the intent record;
- queries/bodies/credentials are absent from central logs.

#### Revocation

Stage 1 validates the proxy's drain/reload behavior with a stub revocation controller. Direct OpenBao polling is `stubbed` until Stage 3.

- UI/service signal denies new requests immediately;
- direct OpenBao version/delete change is detected within the declared maximum interval in Stage 3 and later; Stage 1 records this case as `stubbed`;
- long-lived connections drain/reset;
- replacement uses a new proxy capability and certificate;
- old capabilities remain invalid.

#### Client compatibility

Test at minimum:

- curl;
- Git smart HTTP clone/fetch;
- pip/PyPI preset;
- npm preset;
- Node HTTPS/fetch;
- Python requests/httpx;
- one Java HTTPS client;
- an HTTP/2 client.

If a required client resolves before CONNECT, add an allowlist-only resolver and rerun the entire DNS bypass group.

### 11.3 Conformance applicability by stage

| Group | Stage 1 insecure | Stage 1 Linux/KVM | Stage 3 integrated | Stage 4 EKS |
|---|---|---|---|---|
| Route/parser/credential behavior | Real proxy, fixture secrets | Real proxy, fixture secrets | Real Cogs/OpenBao | Real Cogs/OpenBao |
| Audit/WAL | Stubbed authz/WAL | Stubbed authz/WAL | Real | Real |
| Revocation polling | Stubbed controller | Stubbed controller | Real OpenBao metadata | Real OpenBao metadata |
| Guest-root external bypass | No security claim | Real host enforcement | Real Linux/KVM enforcement | Real CNI/host enforcement |
| Cogs/API port isolation | Not applicable until Cogs | Not applicable until Cogs | Real | Real |
| Kubernetes identity/CNI | Not applicable | Not applicable | Not applicable | Real |

Proxy selection requires the real proxy behavior rows to pass and stub contracts to demonstrate required hooks. Production acceptance requires every mandatory row to be rerun against real Stage 3/4 components.

### 11.4 Proxy candidates

Test at least:

- pinned Envoy;
- one established forward-MITM implementation, initially mitmproxy or a validated Squid configuration.

Selection criteria:

1. passes the security contract;
2. robust HTTP/2 and CONNECT behavior;
3. deterministic immutable configuration;
4. fail-closed authorization hook;
5. structured audit output;
6. connection draining;
7. bounded resource usage;
8. patch/update maturity;
9. deployment and operational simplicity;
10. minimal Cogs-specific code.

Do not select a custom proxy merely because a prototype has fewer lines. A custom implementation requires an additional security review covering request smuggling, TLS, HTTP/2, limits, and parsing.

### 11.5 Integration presets

Implement and test versioned presets for:

- GitHub clone/fetch, including smart-HTTP POST and required artifact/CDN hosts;
- PyPI/pip, including file-host fan-out;
- npm registry/package download.

Each preset specifies exact host groups, methods, path matching, redirect behavior, and whether authentication is injected on each host. A credential must never follow a redirect to a host not explicitly bound to it.

## 12. Stage 1 deliverables

- reusable conformance runner;
- applicability-aware machine and human reports that distinguish stubbed from real dependencies;
- guest network probe;
- upstream fixtures;
- insecure container driver;
- optional macOS VM convenience driver;
- required authoritative Linux/KVM driver;
- proxy adapters/config generators;
- tested integration presets;
- proxy comparison report;
- proxy-selection ADR;
- documented unsupported clients/protocols.

## 13. Stage 1 exit criteria

- [ ] Selected proxy passes all applicable conformance tests in the insecure driver.
- [ ] Selected proxy passes all applicable protocol tests in `macos-vm-dev` when that convenience profile is provided.
- [ ] Selected proxy passes all applicable security tests in the authoritative `linux-kvm` profile with guest root.
- [ ] At least one alternate proxy has been evaluated and documented.
- [ ] No real credential appears in guest-visible data or test logs.
- [ ] Required client compatibility is measured, not assumed.
- [ ] Certificate validity exceeds maximum session lifetime plus margin.
- [ ] Proxy choice is recorded in an ADR.
- [ ] Every audit/revocation result still backed by a stub is clearly identified for mandatory Stage 3 rerun.

---

# Stage 2 — Short-lived AWS nested-virtualization feasibility

## 14. Objective

Answer the AWS runtime question cheaply before investing in EKS-specific implementation.

This stage uses one short-lived EC2 instance, not EKS. It validates nested KVM, Kata/QEMU, image architecture, and basic performance.

## 15. Cost and safety controls

Before launching anything:

- use a dedicated development AWS account;
- configure a small AWS Budget and alerts;
- require explicit manual apply;
- set maximum instance count to one;
- apply owner, purpose, source revision, and expiry tags;
- install an independent TTL cleanup path;
- avoid NAT Gateway, load balancer, EFS, and persistent public IP unless required;
- keep Terraform/OpenTofu state outside the disposable instance;
- provide and test one-command destroy;
- produce a final zero-resource inventory after destruction.

Do not test bare metal unless supported virtual nested virtualization fails or is unacceptable.

## 16. Tasks

### 16.1 Select an instance candidate

- Query current AWS documentation/API for nested-virtualization-capable virtual families.
- Verify availability in the chosen region.
- Prefer the smallest suitable on-demand instance for deterministic testing.
- Record hourly price and quotas before launch.
- Do not encode an instance family permanently until results are known.

### 16.2 Provision the host

Use OpenTofu under `deploy/aws-feasibility/` to create:

- one EC2 host;
- minimal security group restricted to the engineer's source or SSM;
- ephemeral root disk;
- an EC2 launch template whose rendered `CpuOptions.NestedVirtualization` value is `enabled`;
- required nested-virtualization configuration;
- no unrelated platform resources.

Use the AWS-documented KVM/nested-virtualization setup. Do not infer configuration from historical EC2 behavior.

### 16.3 Validate runtime

Capture:

- rendered launch-template CPU options and instance metadata proving the intended option was applied;
- CPU virtualization flags;
- required KVM kernel modules in the selected OS/AMI;
- `/dev/kvm` access;
- KVM self-test;
- Kata/containerd installation;
- Kata sandbox boot;
- root execution inside the sandbox;
- guest kernel identity distinct from host;
- basic network and filesystem behavior;
- QEMU/Kata versions and effective configuration.

### 16.4 Measure

At minimum:

- cold boot to sandbox-ready p50/p95 over repeated runs;
- SSH-ready latency;
- CPU and filesystem overhead relative to a normal container;
- memory overhead per idle sandbox;
- a representative Git checkout/status workload;
- a representative package install/build;
- maximum practical sandbox density estimate;
- observed cost for the campaign.

Run the egress conformance suite where practical, but EKS/CNI-specific enforcement remains Stage 4.

### 16.5 Tear down

- export redacted report;
- destroy all resources;
- query EC2, EBS, Elastic IP, security groups, and related resources for leftovers;
- attach zero-resource evidence to the report.

## 17. Decision outcomes

### Pass

Select the validated virtual family as the Stage 4 candidate, subject to EKS/Kata/CNI validation.

### Conditional pass

Proceed if functional but document performance, region, or cost limitations and identify a second candidate.

### Fail

Evaluate bare metal in a separate explicitly approved cost window. If metal is unacceptable, revisit the reference runtime through an ADR; do not silently use containers.

## 18. Stage 2 exit criteria

- [ ] One supported virtual EC2 type and target region have a measured result.
- [ ] The rendered launch template explicitly enables `CpuOptions.NestedVirtualization`.
- [ ] The selected OS/AMI supplies the required KVM modules.
- [ ] Kata either boots with KVM or failure evidence identifies the blocker.
- [ ] Startup and representative workload performance are recorded.
- [ ] Cost and density implications are documented.
- [ ] Runtime ADR selects virtual nested KVM, metal, or an explicit redesign.
- [ ] All AWS resources are destroyed.

---

# Stage 3 — Complete local Cogs vertical slice

## 19. Objective

Build the complete MVP agent layer locally using the selected proxy and the authoritative Linux/KVM driver. macOS developers may use the convenience VM for iteration, but Stage 3 security exit gates run on Linux/KVM. By the end of this stage, a prompt can drive Pi, execute tools in the VM, use approved secret-injected HTTP, persist a session, link Git state, and emit telemetry.

## 20. Workstream A — Cogs process and protocol

### 20.1 Launch and lifecycle

Implement:

- strict launch-schema validation;
- immutable configuration after readiness;
- signal handling and graceful shutdown;
- readiness dependencies for session storage, SSH, proxy, auth, and audit WAL;
- no local-tool fallback;
- turn-boundary recycle notification;
- emergency hard deadline handling;
- bounded shutdown timeout.

### 20.2 Internal API

Implement the `DESIGN.md` API:

- `POST /v1/input`;
- `POST /v1/abort`;
- `GET /v1/events`;
- `GET /v1/entries`;
- `GET /v1/state`;
- `POST /v1/export`;
- `POST /v1/shutdown`;
- live/ready health endpoints.

Requirements:

- per-worker authentication;
- request body and response size limits;
- daemon request correlation ID;
- bounded LRU duplicate suppression;
- SSE sequence and bounded replay;
- paged append-order history with opaque continuation cursor;
- no raw export through a model-callable tool;
- no cross-session API.

Contract tests must run without a real model or VM.

### 20.3 Pi session

- Promote and harden the APIs proven by the Stage 0 Pi embedding spike; do not rediscover basic feasibility here.
- Construct `AuthStorage`, `ModelRegistry`, `SessionManager`, and `createAgentSession()` explicitly.
- Register only Cogs SDK tools.
- Disable project/global extension discovery and Pi package loading.
- Do not import repository code.
- Preserve native Pi JSONL and branching.
- Map prompt, steer, follow-up, and abort exactly to Pi semantics.
- Forward Pi events through the versioned event envelope.
- Use a fake model/stream function for deterministic tests.
- Add opt-in real-provider integration tests using developer credentials that never run in normal CI.

## 21. Workstream B — SSH/SFTP tools

### 21.1 Connection security

- Require the launch-document host-key pin.
- Reject key mismatch; never prompt or auto-update.
- Use a per-session client key.
- Disable agent forwarding and unrelated SSH features.
- Bound connection, command, idle, and shutdown timeouts.
- Enforce maximum concurrent SSH channels.

### 21.2 Tool behavior

Implement and test:

- `read`: offset/limit, UTF-8 handling, binary behavior, maximum output;
- `write`: temporary upload and atomic rename;
- `edit`: exactly one match, no guessed replacement;
- `bash`: `/workspace` cwd, streaming, cancellation, process-group termination, output truncation, exit/signal reporting.

Direct file tools validate allowed guest paths. Do not parse shell commands as policy.

### 21.3 Adversarial outputs

Test:

- very large output;
- invalid UTF-8;
- ANSI/control sequences;
- long lines;
- process trees and detached children;
- command timeout;
- SSH disconnect during write;
- malicious filenames;
- symlinks within the guest;
- concurrent steer/follow-up during a tool call.

No output may become executable host input.

## 22. Workstream C — model authentication

### 22.1 API keys

- Implement scoped OpenBao retrieval for organization/user model keys.
- Supply API keys through Pi runtime auth.
- Keep values in memory only.
- Redact errors and telemetry.
- Provide environment-based local development credentials outside CI.

### 22.2 OAuth broker client

Define a small external contract:

```text
GetAccessMaterial(user, provider, model) -> short-lived Pi-compatible auth
InvalidateAccessMaterial(reference)
GetExpiry(reference)
```

Cogs must not receive or persist rotating refresh tokens. The local fake broker should simulate:

- token expiry;
- concurrent requests;
- refresh serialization;
- broker outage;
- revoked user authorization.

Production broker implementation belongs to the future daemon/platform. The initial Cogs release is API-key-only by default. Subscription integration remains disabled unless the external team delivers the broker in time for Stage 5, four-session refresh concurrency tests pass, and provider terms have been approved. Track this as a named cross-team dependency from Stage 0 rather than a late release surprise.

## 23. Workstream D — secure egress integration

- Generate immutable route groups from validated presets/configuration.
- Resolve integration secrets through scoped OpenBao handles.
- Obtain the proxy leaf certificate through OpenBao PKI.
- Enforce certificate lifetime margin.
- Place secret-bearing config only in trusted tmpfs.
- Generate/inject the per-session proxy capability.
- Restrict guest reachability to the proxy listener port.
- Add synchronous audit authorization and WAL.
- Poll OpenBao metadata within the configured revocation bound.
- Implement daemon-facing drain/replacement event.
- Run the full applicable Stage 1 suite in every security-relevant change: `insecure-container` on PRs and `linux-kvm` nightly/security-labelled. Replace all Stage 1 `stubbed` audit/revocation results with real Stage 3 results.

If the selected proxy cannot be configured without growing substantial custom code, stop and revisit the proxy ADR.

## 24. Workstream E — skills and project context

### 24.1 Shared skills

- Publish shared skills as an immutable OCI artifact pinned by digest.
- Use a trusted materializer/init path to pull and verify it; registry credentials never enter the guest.
- Load skill prompt text from the verified trusted copy, never through SFTP or from the guest.
- Transfer the same verified archive into the guest over SFTP and expose it read-only where the runtime supports an external read-only mount.
- Verify the guest copy against the same digest before first use; later guest-root mutation changes only the untrusted guest view, not the prompt provenance.
- Record the OCI digest in session metadata and export.

### 24.2 Private skills

- Snapshot user-scoped skills into a content-addressed archive in S3-compatible object storage at session start.
- Ensure another user's trusted identity cannot resolve or fetch it.
- Have the trusted materializer fetch and verify the archive; do not give object-store credentials or a general presigned capability to the guest.
- Load prompt text from the verified trusted copy and transfer that exact archive into the guest over SFTP.
- Treat all content as untrusted instructions even though transport and digest provenance are verified.
- Use MinIO or a filesystem artifact store locally while preserving the same manifest/digest behavior.

### 24.3 Project context

- Retrieve approved files such as `AGENTS.md` over SFTP.
- Treat content and filenames as untrusted.
- Bound file size/count.
- Record load failures without failing the entire session.

## 25. Workstream F — session and Git

### 25.1 Session state

- Store Pi JSONL on trusted storage unavailable to the guest.
- Flush before acknowledging settled boundaries where required by Pi.
- Support paged history from JSONL.
- Preserve Pi compatibility in tests.
- Implement graceful-shutdown bundle generation.

### 25.2 Git observation

All Git commands run through SSH in the sandbox.

- observe `HEAD` before turn, after completed tool-result boundaries, at settle, and shutdown;
- record Pi entry/time authoritatively and Git SHA as an untrusted observation;
- write trusted sidecar mapping;
- attempt non-secret Git note under `refs/notes/cogs`;
- never automatically push notes;
- implement exact/nearest-ancestor/pre-Cogs lookup responses.

### 25.3 Hidden checkpoints

- use a temporary index;
- do not modify `HEAD` or user index;
- respect `.gitignore` and configured exclusions;
- enforce changed-file, per-file, total-size, and timeout limits;
- include dirty human changes in the next checkpoint;
- return warning rather than fail an otherwise completed turn;
- allow operators to disable checkpoints while retaining actual-commit mappings.

Benchmark on small, large, and dirty repositories.

### 25.4 Export

Produce the bundle defined in `DESIGN.md`:

- Pi JSONL;
- hashed manifest;
- Git map;
- skill revisions;
- attachments excluded by default.

Raw export requires explicit authenticated API invocation and is marked sensitive. Do not implement sanitization in this stage; preserve a deterministic transform hook.

## 26. Workstream G — policy and observability

### 26.1 Policy

Implement one static authorization function over the versioned action envelope for:

- mount/config validation;
- tool enable/dispatch;
- egress rule and secret use;
- export mode;
- reserved restore action.

Do not parse bash text. Add contract tests so a future OPA adapter can return equivalent decisions.

### 26.2 OpenTelemetry

Emit spans and metrics from `DESIGN.md`. Add automated assertions that exported telemetry does not contain:

- prompt/model text;
- source;
- complete commands;
- arbitrary paths;
- tool output;
- HTTP query/body;
- secrets/placeholders.

Keep exact command/tool detail in the user transcript. Provide an explicit disabled-by-default enterprise command-audit hook.

## 27. Development launcher

Build a small local CLI/script that:

1. creates or resets the insecure container, optional macOS convenience VM, or authoritative Linux/KVM VM;
2. provisions SSH identity and host-key pin;
3. starts OpenBao, OTLP collector, fixture services, and selected proxy;
4. prepares launch configuration;
5. starts one Cogs worker;
6. submits prompts and tails SSE;
7. requests history/export;
8. shuts down and cleans resources.

It may use static local identity. It must be named and documented as development tooling, with no production auth or scheduler claim.

## 28. Stage 3 exit scenario

The mandatory local demonstration is:

1. Start a clean authoritative Linux/KVM VM and trusted services.
2. Start Cogs with a test user, project, skill revisions, model API key, and one integration preset.
3. Submit a prompt through HTTP.
4. Pi reads and edits a repository and runs tests through SSH/SFTP tools.
5. The sandbox performs one allowed credentialed request without seeing the real credential.
6. A disallowed request fails.
7. Events stream live, then rebuild through paged history after replay eviction.
8. Git commit/checkpoint maps to the correct Pi entry as an untrusted observation.
9. OTLP contains usage/operation metadata but no sensitive content.
10. Raw export opens with the pinned Pi tooling.
11. Shutdown flushes state and removes compute.
12. The egress conformance suite still passes from guest root.

## 29. Stage 3 exit criteria

- [ ] Authoritative Linux/KVM end-to-end scenario passes repeatedly.
- [ ] All Cogs API contracts have deterministic tests.
- [ ] Native Pi JSONL compatibility test passes.
- [ ] API-key model calls work; OAuth broker concurrency is simulated.
- [ ] No extension/package/project code executes in the trusted worker.
- [ ] Egress conformance passes after Cogs integration, with Stage 1 audit/revocation stubs replaced by real results.
- [ ] Git/skill/session integrity claims match `DESIGN.md` wording.
- [ ] No normal CI job requires AWS.
- [ ] Production code remains in the 3,000–5,000-line planning range, or a scope/architecture ADR explains and approves the deviation.

---

# Stage 4 — Ephemeral EKS and NIC integration

## 30. Objective

Validate the complete production topology on EKS using the Stage 2 runtime candidate and Stage 3 Cogs implementation. This environment is created for test campaigns and destroyed afterward.

## 31. AWS environment controls

- dedicated development account;
- AWS Budget and alerts active;
- all resources TTL-tagged;
- manual approval for apply;
- hard node-group maximum initially one;
- no public user ingress;
- no daemon implementation;
- no persistent production data;
- explicit destroy and zero-resource verification;
- expand capacity only for a named test requiring it.

The EKS control plane incurs cost even with zero nodes; destroy the cluster between campaigns.

## 32. NIC and infrastructure tasks

### 32.1 Dedicated sandbox node group

Add or configure through NIC:

- validated nested-virtualization instance type and target region;
- a custom EC2 launch template with `CpuOptions.NestedVirtualization=enabled`;
- verification that NIC's node-group abstraction can express and preserve the launch-template ID/version, extending NIC if necessary;
- an EKS node AMI with required KVM modules loaded/available;
- labels and taints dedicated to Kata sandboxes;
- KVM exposure required by the chosen Kata deployment;
- minimum/desired/maximum capacity suitable for the campaign;
- no trusted platform workload scheduling on sandbox nodes;
- pinned node image/runtime versions.

Keep trusted Cogs/proxy resources on ordinary trusted nodes.

### 32.2 Kata installation

- install Kata through a reviewed cluster-scoped mechanism;
- define explicit `RuntimeClass`;
- pin release and configuration;
- verify the sandbox pod contains no trusted sidecar;
- verify guest kernel identity;
- validate runtime cleanup after pod deletion;
- document operator upgrade procedure.

### 32.3 Storage

- use EBS/CSI block volume for active project workspace;
- test attach, mount, detach, reattach, and forced-worker-loss behavior;
- ensure one writer per project lease;
- use separate trusted storage for Pi session state;
- test storage deletion and retention behavior;
- avoid EFS as the default Git/build workspace unless benchmarks justify it.

### 32.4 Network

Create per-session or equivalently strict policies:

- sandbox ingress only from assigned worker SSH source;
- sandbox egress only to assigned proxy listener and optional exact allowlist DNS resolver;
- deny Cogs API/admin/OpenBao/Kubernetes API/metadata;
- cover IPv4 and IPv6;
- block UDP;
- test policy after guest root alters guest routes/firewall;
- validate behavior with the actual EKS CNI configuration.

NetworkPolicy is secondary to proxy capability authentication, not a replacement.

### 32.5 Identity and secrets

- worker receives a scoped Kubernetes identity;
- sandbox receives no service-account token;
- OpenBao role can resolve only launch-document handles for that user/session;
- proxy capability is session-specific;
- CA private key remains in OpenBao;
- proxy admin endpoints remain worker-private;
- verify Kubernetes Secret/Pod specs contain no real integration values.

## 33. Helm Software Pack

Implement chart values for:

- worker image and resources;
- sandbox image and `RuntimeClass`;
- trusted/sandbox node selectors and tolerations;
- OTLP endpoint;
- OpenBao endpoint/roles/PKI path;
- public egress CA distribution;
- workspace and session StorageClasses;
- network-policy selectors/ports;
- integration preset artifacts;
- shared-skill OCI registry/reference and trusted materializer;
- private-skill S3-compatible artifact endpoint/materializer configuration;
- idle and hard lifecycle limits;
- audit WAL storage limits;
- development-only insecure driver disabled by default.

Add preflight checks for:

- supported instance type/region and rendered launch-template nested-virtualization option;
- KVM-capable node and required AMI kernel modules;
- Kata `RuntimeClass`;
- CNI NetworkPolicy enforcement;
- required CSI modes;
- OpenBao reachability and role;
- OTLP configuration;
- IPv6 and UDP deny behavior;
- required proxy certificate validity.

A missing production prerequisite fails installation/readiness. It must not switch to `runc`.

## 34. Temporary resource launcher

Until the daemon exists, provide an integration-test launcher that creates:

- one trusted worker/proxy Pod and internal Service;
- one Kata sandbox Pod;
- one workspace PVC and trusted session-state PVC;
- per-session NetworkPolicies;
- public CA and non-secret configuration;
- ephemeral SSH and proxy identities;
- immutable launch document.

The launcher may hold development cluster credentials. It is test tooling and must not be shipped as the future production daemon.

## 35. EKS validation campaigns

### 35.1 Security campaign

Run the complete conformance suite from guest root and preserve evidence. Add EKS-specific attempts:

- Kubernetes API/service discovery;
- node/kubelet endpoints;
- instance metadata;
- other Pods and Services;
- worker API/admin ports;
- PVC paths not assigned to the session;
- another session's proxy capability and Service;
- deletion/recreation identity reuse.

### 35.2 Functional campaign

Run the Stage 3 end-to-end scenario using:

- actual Kata sandbox;
- actual EBS workspace;
- actual OpenBao Kubernetes auth;
- actual OTLP collector;
- selected proxy;
- real Pi API-key model integration.

### 35.3 Performance campaign

Measure:

- worker start;
- Kata Pod scheduled-to-SSH-ready p50/p95/p99;
- first-tool latency;
- workspace attach latency;
- idle resource overhead;
- representative Git and build performance;
- proxy latency overhead;
- graceful drain/recycle duration.

The target is under 30 seconds to sandbox readiness at the agreed percentile. Record failures rather than hiding image-pull or scale-from-zero time.

### 35.4 Recovery campaign

Test:

- worker crash;
- sandbox crash;
- node loss;
- proxy crash;
- OpenBao outage;
- OTLP outage;
- session-volume transient failure;
- audit WAL full;
- network-policy removal attempt;
- forced eight-hour-equivalent recycle at turn boundary.

No prompt is automatically replayed after an unknown outcome.

## 36. Stage 4 exit criteria

- [ ] Kata guest root cannot bypass external network controls.
- [ ] Sandbox has no Kubernetes/cloud/OpenBao credentials.
- [ ] Complete local conformance suite passes unchanged on EKS with no mandatory `stubbed` result.
- [ ] EBS workspace lifecycle works without concurrent writers.
- [ ] Real Pi end-to-end scenario passes.
- [ ] p95 or agreed startup percentile is under 30 seconds, or a reviewed exception/plan exists.
- [ ] All failure modes match `DESIGN.md`.
- [ ] Helm/NIC install and destroy are repeatable.
- [ ] No silent container fallback exists.
- [ ] Test cluster and related AWS resources are destroyed.

---

# Stage 5 — Pre-release security, resilience, scale, and operations

## 37. Objective

Turn the validated implementation into a release candidate with defensible security evidence, operational limits, capacity guidance, and a bounded known-risk register.

Stage 5 is not routine development on a permanently running cluster. Use scheduled, time-boxed AWS campaigns and destroy afterward.

## 38. Release candidate controls

- freeze exact source revision;
- pin image digests and dependency lockfiles;
- generate SBOM and vulnerability report;
- record Kata/QEMU/kernel/proxy/OpenBao versions;
- define supported AWS regions/instance types;
- prohibit configuration drift during a test campaign;
- use synthetic repositories and credentials;
- predeclare maximum AWS spend and node count;
- require manual approval before each scale step.

## 39. Security validation

### 39.1 Repeat full conformance

Run every acceptance criterion from `DESIGN.md` on the release candidate. No skipped security test is acceptable without a written release-blocking or risk-acceptance decision.

### 39.2 Independent review

Request review focused on:

- Pi resource loading and extension disabling;
- SSH host-key and channel handling;
- path handling and SFTP atomicity;
- proxy CONNECT/TLS/HTTP normalization;
- header stripping and redirect handling;
- route-group presets;
- proxy capability scope;
- OpenBao policies and PKI;
- audit fail-closed behavior;
- Kubernetes NetworkPolicies and service-account mounts;
- guest image and Kata configuration;
- sensitive-data logging;
- Git and skill integrity claim wording.

### 39.3 Supply-chain review

- verify image signatures/digests;
- review direct dependencies and licenses;
- scan transitive dependencies;
- remove unused packages/tools from trusted worker image;
- document patch cadence for Node, Pi, SSH library, proxy, Kata, QEMU, kernel, and OpenBao;
- prove project dependencies cannot alter trusted worker packages.

### 39.4 OAuth readiness

Before declaring subscription support:

- obtain product/legal confirmation for each provider's intended use;
- test against the real external broker, not per-worker refresh files;
- run four concurrent sessions for one user/provider through expiry/refresh;
- prove one owner rotates the refresh token;
- test revocation and account switch;
- remove subscription support from the advertised matrix if either terms or concurrency safety is unresolved.

API-key support is not blocked by subscription readiness.

## 40. Scale and performance validation

### 40.1 Ramp plan

Do not jump directly to 250 real sandboxes. Run controlled steps:

1. 10 active sessions;
2. 25;
3. 50;
4. 100;
5. 250 only after prior steps meet safety, cost, and stability gates.

At each step record:

- requested and actual CPU/memory;
- node count and bin-packing;
- startup p50/p95/p99;
- failed scheduling and image pulls;
- Pi/model latency separately from infrastructure latency;
- proxy CPU/memory/connections;
- OpenBao request rate;
- SSH channel/error rate;
- storage latency and throughput;
- OTLP and audit-WAL backlog;
- cost per active-session hour;
- cleanup/recycle success.

Use mocked model responses for infrastructure saturation tests to avoid uncontrolled token cost. Use a smaller representative real-model sample for end-to-end latency and usage telemetry.

### 40.2 User concurrency

Validate:

- default four sessions per user;
- configurable higher limit;
- exclusive writer lease on the same project;
- simultaneous sessions on different project volumes;
- one user's sessions cannot access another user's storage, skills, proxy, history, or telemetry details.

### 40.3 Resource classes

Verify default, large, and maximum classes:

| Class | CPU | Memory |
|---|---:|---:|
| Default | 2 | 4 GiB |
| Large | 4 | 8 GiB |
| Maximum | 8 | 16 GiB |

Test 20 GiB ephemeral disk, output limits, command timeouts, idle shutdown, and emergency hard deadline.

## 41. Reliability and destructive testing

Inject and document:

- abrupt worker termination during model stream;
- sandbox termination during file write;
- proxy termination during request;
- credential revocation during HTTP/2 connection;
- OpenBao loss and stale metadata;
- OTLP loss and recovery;
- full audit WAL;
- full workspace disk;
- EBS detach delay;
- node drain and replacement;
- duplicate input request;
- SSE disconnect beyond replay buffer;
- malformed JSONL tail after abrupt storage failure;
- Git repository corruption;
- oversized skill artifact;
- hostile tool output.

Expected outcomes must match the failure table in `DESIGN.md`. Unknown prompt outcomes are reported; they are never silently replayed.

## 42. Privacy and deletion validation

- inspect OTLP, worker logs, proxy logs, Kubernetes events, crash dumps, and reports for prompt/source/secret leakage;
- test user deletion across session storage and object copies;
- test object version deletion where configured;
- verify legal-hold behavior is explicit and separate;
- verify raw export is unavailable to the model;
- verify attachments are excluded by default;
- verify default retention is 30 days;
- confirm query strings and request bodies never enter central network audit.

## 43. Operational documentation

Produce:

1. installation and prerequisite guide;
2. NIC configuration guide;
3. local development guide;
4. supported/unsupported platform matrix;
5. runtime and proxy upgrade runbook;
6. OpenBao policy and revocation runbook;
7. incident response for suspected credential exposure;
8. node/runtime CVE response procedure;
9. backup, retention, export, and deletion guide;
10. capacity and cost planning guide;
11. observability dashboard field reference;
12. known limitations and residual risks;
13. teardown and orphan-resource verification guide.

Every production claim should link to an automated test or a clearly stated assumption.

## 44. Final release-readiness report

The staff engineer owns a final report containing:

- source and image digests;
- completed acceptance matrix;
- proxy and runtime ADRs;
- AWS instance/region matrix;
- conformance reports;
- independent review findings and resolutions;
- vulnerability/SBOM summary;
- p50/p95/p99 performance;
- tested concurrency and cost;
- failure-injection outcomes;
- privacy/deletion results;
- OAuth support decision;
- known risks with owners;
- go/no-go recommendation.

## 45. Stage 5 exit criteria

- [ ] All mandatory `DESIGN.md` acceptance tests pass on release artifacts with real dependencies; no `stubbed` result satisfies release acceptance.
- [ ] Independent security review has no unresolved critical/high finding.
- [ ] Proxy and AWS runtime are selected through recorded evidence.
- [ ] OAuth subscription support is either safe/permitted or explicitly disabled.
- [ ] At least 50 real concurrent sandboxes are validated; higher steps run according to cost-approved release goals.
- [ ] The advertised concurrency maximum does not exceed the highest successfully validated real load. Claiming support for 250 requires completing the 250-sandbox step; extrapolation alone is planning evidence, not a support claim.
- [ ] Failure-injection outcomes match documented behavior.
- [ ] Central telemetry/logs pass sensitive-data inspection.
- [ ] Backup/export/deletion behavior is verified.
- [ ] Installation, upgrades, incidents, and teardown have runbooks.
- [ ] AWS cost report and zero-resource teardown evidence are complete.
- [ ] Residual risks are published without overstating guarantees.
- [ ] Staff engineer issues a documented go/no-go recommendation.

---

## 46. Cross-stage test matrix

| Test layer | Local container | macOS VM dev | Linux/KVM | Single EC2 | EKS Kata | Release load |
|---|---:|---:|---:|---:|---:|---:|
| Unit/schema/API | Yes | Optional | Yes | No | Yes | Yes |
| Pi embedding/JSONL compatibility | Yes | Yes | Yes | No | Yes | Yes |
| SSH/SFTP contract | Yes | Yes | Yes | Yes | Yes | Sample |
| Proxy protocol behavior | Yes | Yes | Yes | Optional | Yes | Yes |
| Guest-root external bypass | No security claim | No authoritative claim | Yes | Partial | Authoritative profile | Sample |
| Kata/KVM | No | No production claim | Yes | Yes | Yes | Yes |
| CNI/NetworkPolicy | No | No | Host controls only | No | Yes | Yes |
| EBS lifecycle | No | No | No | Optional | Yes | Yes |
| OpenBao local token | Yes | Yes | Yes | No | No | No |
| OpenBao workload identity | No | No | No | No | Yes | Yes |
| OTLP privacy | Yes | Yes | Yes | Optional | Yes | Yes |
| Failure injection | Partial | Partial | Yes | Partial | Yes | Yes |
| Scale/cost | Simulated | Small | Small | Density estimate | Moderate | Full approved ramp |

---

## 47. Required ADR decision points

Implementation must pause for an ADR at these points:

1. selected proxy;
2. AWS virtual nested KVM versus bare metal;
3. any replacement for Kata;
4. any need for a custom guest daemon instead of SSH;
5. any inline/dynamic secret mechanism replacing immutable config;
6. any relaxation of default-deny networking;
7. any trusted worker mount of untrusted workspace data;
8. any central logging of raw commands/prompts/tool output;
9. any subscription OAuth path that exposes refresh tokens to workers;
10. any production Kubernetes controller added to Cogs;
11. any database introduced;
12. any silent fallback from VM to container.

---

## 48. Initial issue/epic breakdown

### Epic A — Foundation *(Small)*

- repository/CI setup;
- Pi embedding hello-world and hostile discovery canaries;
- schemas and contract tests;
- image builds/SBOM;
- Linux/KVM runner selection;
- skill artifact transport ADR;
- initial ADRs;
- applicability-aware security-report schema.

### Epic B — Egress conformance *(Extra large)*

- fixture upstream;
- guest probe;
- audit fault injector;
- insecure driver;
- macOS convenience driver;
- authoritative Linux/KVM driver;
- request-smuggling probes;
- Envoy adapter;
- alternate proxy adapter;
- GitHub/PyPI/npm presets;
- proxy ADR.

### Epic C — AWS runtime spike *(Small)*

- OpenTofu single-instance environment;
- launch-template `CpuOptions.NestedVirtualization` validation;
- nested KVM/AMI module validation;
- Kata install;
- measurements;
- teardown evidence;
- runtime ADR.

### Epic D — Cogs core *(Large)*

- launch/lifecycle;
- API/SSE/history;
- Pi session;
- SSH/SFTP tools;
- policy;
- OTel;
- development launcher.

### Epic E — Auth and egress *(Large)*

- OpenBao API keys;
- PKI;
- proxy generation;
- capability binding;
- audit WAL;
- revocation;
- OAuth broker contract/fake.

### Epic F — State and reproducibility *(Medium–large)*

- session storage;
- skills artifacts;
- project context;
- Git mapping/checkpoints;
- export.

### Epic G — EKS/NIC *(Extra large)*

- custom launch template and NIC node-group support;
- sandbox node group;
- Kata RuntimeClass;
- EBS storage;
- NetworkPolicy;
- Helm pack;
- temporary integration launcher;
- EKS evidence.

### Epic H — Release readiness *(Extra large)*

- independent review;
- supply chain;
- load ramp;
- failure injection;
- privacy/deletion;
- runbooks;
- final report.

### External dependency I — Subscription OAuth broker *(daemon/platform team)*

- assign owner and target milestone during Stage 0;
- confirm provider terms for server-hosted use;
- implement single-owner rotating refresh-token service outside Cogs;
- expose the short-lived access-material contract;
- complete four-session concurrency/revocation tests before Stage 5 support declaration;
- if unavailable, keep the release API-key-only and mark subscription OAuth disabled.

---

## 49. Definition of done for every implementation PR

A PR is not complete unless:

- behavior has unit or contract tests;
- security-sensitive behavior has a negative test;
- no new sensitive fields enter logs/telemetry;
- schemas/docs are updated when contracts change;
- dependency additions are justified;
- image and package locks remain deterministic;
- insecure behavior is labelled and cannot be enabled by production defaults;
- relevant conformance tests pass;
- an ADR is included when a decision point in section 47 is crossed.

---

## 50. Immediate next actions

Execute these in order:

1. Initialize Git, TypeScript, CI, complete schemas, and ADR directory.
2. Run the Stage 0 Pi embedding hello-world with hostile extension/package canaries and JSONL round-trip.
3. Select a maintained Linux/KVM runner and configure the PR/nightly conformance schedules.
4. Decide skill artifact transport and open the external OAuth-broker dependency with an owner or explicit API-key-only release decision.
5. Scaffold `test/egress-conformance/` with applicability-aware reports.
6. Build the insecure `sshd` driver and upstream TLS fixture.
7. Implement allowed/denied/header-overwrite and request-smuggling tests.
8. Add Envoy and alternate-proxy adapters, using stubbed audit/revocation dependencies where documented.
9. Provision the authoritative Linux/KVM profile and rerun the suite as guest root; use macOS VM tooling only for convenience.
10. Select the proxy through an ADR.
11. Perform the one-instance AWS Stage 2 campaign with explicit launch-template CPU options, then destroy it.
12. Return to local development for the Stage 3 Cogs vertical slice and replace stubbed security results with real integrations.

Do not begin with EKS, a production daemon, app deployment, sanitization, or a generalized plugin framework.
