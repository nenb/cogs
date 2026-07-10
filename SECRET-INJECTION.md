# Agent Secret Injection Patterns

## Goal

Run agents/notebooks that can call external APIs without exposing raw credentials to the workload. The workload calls normal upstream URLs; a trusted network/control-plane component injects credentials at egress.

Core guarantee:

> The agent can use a credentialed integration, but cannot read the credential value from env vars, files, the vault, or request headers.

This reduces secret exfiltration risk, but does **not** prevent the agent from exfiltrating data returned by the API. Treat the agent as a possible confused deputy.

## Reference Pattern

```text
agent/notebook pod
  ├─ workload container: no secret access, no NET_ADMIN
  ├─ Envoy sidecar: intercepts outbound HTTP(S), injects credentials
  └─ init containers:
       1. install local CA into trust stores
       2. install iptables/nftables redirect rules

OpenBao/Vault: stores users/{username}/{tool}
Tool registry: declares hosts, auth type, egress policy
Secrets UI: user connects/revokes integrations
Identity: Keycloak/JupyterHub/Kubernetes/OpenBao policy binding
```

Typical TLS request flow:

1. Tool calls `https://api.example.com` normally.
2. iptables redirects traffic to Envoy.
3. Envoy presents a cert signed by the injected local CA.
4. Envoy reads plaintext HTTP request.
5. Envoy fetches/holds the user credential from OpenBao via SDS or equivalent.
6. Envoy injects auth.
7. Envoy opens verified TLS to the real upstream.
8. Response returns to the workload.

If no credential is configured, fail closed with `401`; do not forward unauthenticated.

## What Istio/Kubernetes Proves

Istio, Linkerd, and AWS App Mesh validate the *traffic interception substrate*:

- sidecar proxy pattern
- init-container/CNI iptables redirects
- Envoy/xDS/SDS control planes
- mTLS and telemetry inside a mesh
- operator familiarity with these mechanisms

They do **not** automatically solve transparent credential injection into arbitrary third-party HTTPS APIs. This design reuses service-mesh plumbing, but credential injection, TLS MITM, request signing, and egress policy are custom application-layer concerns.

More accurate framing:

> Use Istio-style transparent traffic capture as the substrate; build explicit credential-injection and signing behavior per supported auth/protocol class.

## Tool Registry Shape

A registry entry should define:

- tool name
- primary host
- allowed destinations
- auth scheme
- secret path template
- whether auth is simple injection, signing, upstream TLS, or protocol-specific

Example classes:

```yaml
- name: openai
  host: api.openai.com
  allowed_destinations: [api.openai.com]
  auth:
    type: bearer_header
    header: Authorization
    prefix: "Bearer "
    secret_path: users/{username}/openai

- name: aws-bedrock
  host: bedrock.us-east-1.amazonaws.com
  allowed_destinations:
    - bedrock.us-east-1.amazonaws.com
    - s3.amazonaws.com
  auth:
    type: sigv4_signing_proxy
    region: us-east-1
    service: bedrock
    secret_path: users/{username}/aws
```

Avoid claiming all tools are identical. A uniform YAML shape is fine, but implementation complexity differs sharply by auth/protocol type.

## Compatibility Classes

### Works Well

- HTTP/HTTPS APIs with bearer tokens
- API keys in headers
- Basic auth
- OAuth2 access-token injection
- gRPC metadata injection, if Envoy terminates HTTP/2

### Requires Custom Signing Logic

- AWS SigV4
- HMAC-authenticated APIs
- body/header canonical signatures
- presigned URL flows
- streaming/chunked signing

For these, the proxy must sign the **final** request. Modifying a request after the client signs it invalidates the signature.

### Requires Upstream TLS Identity Handling

- mTLS where Envoy owns the client certificate can work.
- mTLS where the application must prove possession of the key end-to-end does not work transparently.

### Requires Protocol-Specific Proxies

Transparent HTTP header injection does not work for:

- Postgres/MySQL
- Redis
- SSH/SFTP
- SMTP/IMAP
- AMQP/MQTT
- arbitrary binary protocols

Envoy can allow/block or TCP-proxy these, but cannot inject HTTP credentials into non-HTTP protocols.

## Common Failure and Bypass Cases

- **Certificate pinning:** client rejects Envoy’s generated cert.
- **Custom trust stores:** Java, certifi, Conda, Node, Go static binaries, or proprietary tools may ignore system CA.
- **SDK preflight credential checks:** SDK refuses to send without an env var/key. Use non-secret placeholders and have Envoy overwrite/strip them.
- **AWS SigV4 / HMAC:** in-flight mutation breaks signatures unless Envoy signs the final request.
- **Application-level body encryption:** Envoy can inject headers but cannot inspect or modify encrypted payloads.
- **mTLS key possession:** fails if upstream requires the workload itself to hold the private key.
- **HTTP/3/QUIC/UDP:** TCP iptables rules do not catch UDP/443. Block UDP/443 or explicitly proxy it.
- **IPv6 bypass:** configure ip6tables/nftables or disable IPv6.
- **ECH/encrypted SNI:** can interfere with hostname-based TLS interception.
- **Host-header spoofing:** Envoy must route by validated SNI/Host to configured upstreams, not original arbitrary IPs.
- **CONNECT/tunnels/DoH/WebSockets:** agents can tunnel exfiltration through allowed hosts if upgrades/tunnels are not controlled.
- **Wildcard egress:** `allowed_destinations: "*"` is effectively pod-wide open egress.
- **Excluded Envoy UID bypass:** if workload can run as Envoy’s excluded UID, it can bypass interception.
- **Privileged workload:** `NET_ADMIN`, `CAP_SETUID`, root, hostNetwork, or privileged pods can bypass policy.
- **Envoy admin/SDS exposure:** workload must not reach admin or secret-discovery endpoints.
- **Long-lived connections:** revocation may not affect already-established HTTP/2, gRPC, or WebSocket streams unless connections are drained.
- **SDS/control-plane outage:** Envoy may continue using last-known secrets until reconnect; alert on stale streams.

## Security Controls

- Run workload non-root; drop all Linux capabilities.
- Grant `NET_ADMIN` only to the iptables init container.
- Install CA before enabling interception.
- Cover IPv4 and IPv6; block UDP/443 unless supported.
- Deny by default; route only registry-declared hosts.
- Validate SNI, Host, and `:authority` consistency.
- Overwrite or strip any workload-supplied auth headers.
- Fail closed when a secret is absent/revoked.
- Keep Envoy admin/SDS endpoints inaccessible to workload.
- Use short-lived credentials where possible.
- Drain/reset upstream connections on revocation.
- Ship Envoy access logs centrally.
- Use Kubernetes NetworkPolicy as a second egress layer.
- Consider OPA/Gatekeeper/Kyverno for pod policy enforcement.

## Audit Logging

Envoy should emit structured logs for every intercepted request:

```yaml
timestamp: 2024-03-01T14:23:01.442Z
user: alice
pod: agent-pod-abc123
tool: openai
upstream_host: api.openai.com
method: POST
path: /v1/chat/completions
response_code: 200
duration_ms: 843
bytes_sent: 1204
bytes_received: 3891
secret_injected: true
```

These logs are the main audit trail for credentialed API usage.

## Edits

Proposed changes to fold into this document. These arise from reviewing the v0.2 architecture doc against this file. Each item is something that is either missing here, understated, or that the v0.2 doc gets wrong and should not be adopted.

### Framing / guarantees

- **State the guarantee narrowly, up front.** The protection is "the workload cannot read the credential *value*." It does **not** prevent the agent from misusing the credential (confused deputy) or exfiltrating data the API returns. Reject any framing (as in v0.2) that markets egress allow-listing as a general security boundary.
- **Reject "all tools are identical in shape."** A uniform YAML declaration is fine; implementation cost differs sharply by auth class. Keep the tiered taxonomy in Recommended MVP as the authoritative model. Call out explicitly that SigV4/HMAC signing and OAuth2 client-credentials are *not* header injection.
- **Correct the "one SDS stream / native OpenBao SDS" claim.** OpenBao does not natively speak Envoy xDS/SDS. A bridge is required (vault-agent + file SDS, or a small xDS control plane e.g. go-control-plane). There are two SDS sources: credentials (via the bridge) and TLS certs (via k8s SDS / cert-manager). Say so.
- **Correct "revocation is instant."** True for *new* requests. Established HTTP/2, gRPC, SSE, and WebSocket streams stay authenticated until drained. Revocation must reset upstream connections, not just gate new ones. (Already noted in Common Failure cases; promote it so it isn't oversold elsewhere.)

### Substrate hardening (egress capture)

- **The transparent-SDK example is broken without a placeholder credential.** Many SDKs (e.g. OpenAI Python) raise at client construction if no key is present, before any network call — so Envoy never gets to inject. Seed a **non-secret placeholder** into the workload env and have Envoy strip/overwrite it. Add a worked example showing this.
- **Cover IPv6.** The v0.2 rules are IPv4 `iptables` only. Add `ip6tables` (or disable IPv6 in the pod). Without this the agent bypasses interception over IPv6.
- **Block or proxy UDP/443 (QUIC/HTTP/3).** TCP-only redirect rules do not catch QUIC; modern clients negotiate it. Block UDP/443 unless explicitly proxied.
- **Redirect all TCP egress, not just 443/80.** An API or exfil endpoint on any other port bypasses a `--dport 443/80`-only rule. Redirect all TCP with explicit exceptions (loopback, Envoy UID, control-plane hosts).
- **The Envoy-excluded UID is also a bypass hole.** If the workload can run as (or setuid to) Envoy's UID, it escapes the redirect. Pin the workload to a fixed non-Envoy UID, `runAsNonRoot`, `allowPrivilegeEscalation: false`, drop `CAP_SETUID`. Document the UID exclusion as loop-prevention *and* an escape hatch that these controls close.

### TLS interception

- **Init-container trust-store install does not propagate.** `update-ca-certificates` in the `tls-setup` init container mutates only that container's rootfs; pod containers don't share filesystems except mounted volumes. Deliver the CA via a **shared read-only volume** (or bake into images), not by running the install in an init container that then exits.
- **`NODE_EXTRA_CA_CERTS` via `/etc/environment` will not be read.** `/etc/environment` is a PAM (`pam_env`) login mechanism; Kubernetes does not source it. Set trust-store env vars as real container env vars: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`, `AWS_CA_BUNDLE`, `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`, plus Java cacerts (`keytool`).
- **certifi append is per-install only.** Data-science pods have many Python envs (conda, venvs, vendored `certifi`/`requests`). Appending to one `certifi.where()` misses the rest — rely on the env vars above as the primary mechanism.
- **Envoy cannot mint per-SNI leaf certs on the fly** (it is not mitmproxy/SSL-bump). Because egress is allow-listed, pre-provision a single leaf cert whose SANs enumerate every registered upstream host, signed by the local CA, and rotate it when the registry changes. Never expose the CA *private key* to the workload.

### Routing / egress policy

- **Do not route or bind credentials on the client-supplied Host header alone.** The Host header is workload-controlled. Route on validated **SNI**, enforce `SNI == Host == :authority` consistency, and have Envoy dial the *resolved registered hostname*, never the captured original-destination IP. Otherwise an agent can decouple an injected credential from its intended upstream.
- **Control tunnels/upgrades.** HTTP `CONNECT`, WebSocket upgrades, and DNS-over-HTTPS to an allowed resolver defeat the egress allow-list. Reject or explicitly control these.
- **Wildcard egress is pod-wide.** Keep the existing note; grant `*` only to a named browser tool and document the pod-level implication.

### Control plane

- Add an explicit OpenBao→Envoy SDS bridge component to the reference architecture.
- For tool-registry changes reaching running pods: default to **respawn** for the MVP; add a live-reload xDS controller only if long-running JupyterHub sessions require mid-session tool availability.

## Secondary Edits — deployment topology

The primary document (and the v0.2 architecture) assumes an Envoy **sidecar co-located with the workload** (k8s pod / container-in-VM). The actual target is different: an agent harness on the **host** driving risky operations inside a **VM**, with credentials held on the host. Two topologies satisfy this, and they are not equivalent — the difference that matters is **where the interception boundary sits relative to the VM's trust domain.**

```text
Model A (ideal)  — inject at the VM egress boundary, on the host
  host: harness + credentials + OpenBao + Envoy (CA private key)
  vm:   workload only + CA *public* cert in trust store
  interception boundary is OUTSIDE the VM

Model B (fallback) — inject via a proxy container inside the VM
  host: harness + credentials + OpenBao
  vm:   workload + Envoy (CA private key + credentials in memory)
  interception boundary is INSIDE the VM
```

Prefer **Model A**. Fall back to **Model B** only if Model A's host-side plumbing is prohibitive *and* the in-VM workload can be de-privileged (see the conflict note under Model B).

### Common to both

- TLS interception is unavoidable for header injection, so the VM must trust the proxy's CA **public cert** in both models. All the trust-store work from the primary Edits (per-runtime env vars: `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `AWS_CA_BUNDLE`, `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`, Java cacerts; certifi caveat) still applies **inside the VM**. This cost does not go away in either model.
- OpenBao and the OpenBao→Envoy bridge stay on the host in both models. The credential *store* never enters the VM either way; the models differ only in whether the *injection point* (and thus credential *values* in proxy memory + the CA private key) enter the VM.
- The proxy-layer edits (SigV4/HMAC signing, OAuth2 token lifecycle, placeholder-credential-for-SDK-preflight, strip/overwrite client auth headers, fail-closed, SNI-bound routing, tunnel/upgrade control) are substrate-independent and apply unchanged.

### Model A — host-side injection at the VM egress boundary (ideal)

Differences required versus the sidecar model:

- **Interception moves to the host and changes netfilter chain.** VM egress is *forwarded/transit* traffic arriving on the VM's tap/bridge, not host-local traffic. The v0.2 rule (`iptables ... -A OUTPUT ... REDIRECT`) is the wrong chain — `OUTPUT` only catches host-locally-generated packets. Intercept in **`PREROUTING`** on the tap/bridge interface. Use **TPROXY** (mangle `PREROUTING` + policy routing + Envoy transparent listener) as the recommended target: it preserves the original destination and source without NAT and handles UDP; `REDIRECT`/DNAT can also work (original dst recovered via `SO_ORIGINAL_DST` from conntrack) but is NAT-based and weaker for UDP. Enable `ip_forward` on the host.
- **Trust material splits cleanly.** CA **public cert** → VM trust stores. CA **private key** → host Envoy only. A compromised VM cannot mint certs. Credentials and Envoy memory stay on the host.
- **New requirement: identity attribution at the host proxy.** In the sidecar model, identity came from the pod's SDS scope (one Envoy = one user). On the host, one Envoy may serve multiple VMs, so it must map **source VM → user identity → credential scope** (`users/{username}/{tool}`) at connection time — by tap interface / source address / VM ID, or by running one Envoy instance per VM. This machinery is net-new and does not exist in the sidecar model; call it out explicitly.
- **Security upside — the reason to prefer A: the interception boundary is outside the workload's control.** The in-VM workload cannot bypass injection by changing UID, adding/flushing iptables rules, disabling IPv6, or negotiating QUIC — because capture happens outside the VM. Consequently the primary edits about the **Envoy-UID exclusion bypass** and **in-VM privilege hardening** largely *disappear*: the workload may even run as **root inside the VM** without breaking the guarantee (short of a hypervisor escape).
- **Egress hardening becomes authoritative on the host.** Default-deny all VM egress except via Envoy; handle IPv6, UDP/443 (QUIC), and non-443/80 ports at the host tap — the VM cannot undo any of it.
- **Costs (why it might be "too hard").** TPROXY + policy-routing plumbing; multi-tenant identity attribution at the proxy; still must provision the CA cert + trust env vars into the VM.

### Model B — proxy container inside the VM (fallback)

This is the sidecar model with "pod" = "VM." Differences and added requirements:

- **Interception is in-VM** iptables/nftables set up at VM boot (systemd unit or entrypoint), same ordering as the primary doc: CA/trust store ready **before** interception starts. `REDIRECT`-on-`OUTPUT` is valid here because traffic is VM-local-originated.
- **The strong-isolation property is lost.** Both the CA **private key** and the credential **values** (in Envoy's memory) now live inside the VM. The guarantee reduces to the in-VM boundary between workload and proxy. **All** primary-edit hardening now applies *inside the VM*: workload **non-root**, no `NET_ADMIN`, pinned off Envoy's UID, no `CAP_SYS_PTRACE` (seccomp), Envoy admin bound loopback and unreachable by the workload, CA-key and any SDS socket file readable only by Envoy's UID.
- **Conflict to flag prominently.** If the harness needs the in-VM workload to be **root/privileged** to do its "risk operations," Model B's guarantee collapses — VM-root can read Envoy's memory, flush the in-VM iptables, or run as Envoy's UID and bypass. Model B is sound **only** if the risky workload can be de-privileged. If it cannot, Model A is not a preference but a requirement.
- **New requirement: in-VM proxy must authenticate to the host secret store.** The in-VM Envoy fetches credentials from host OpenBao over a host-only channel (vsock or a host-local address). Because the workload shares the VM's network identity, OpenBao cannot distinguish workload from Envoy by network alone — Envoy needs a **per-VM bootstrap credential provisioned to the Envoy container only** (not readable by the workload), with OpenBao policy scoping that identity to this user's secrets. That bootstrap secret is itself sensitive and must be protected from the workload.
- **Simpler bits.** Identity is per-VM (one user) — no multi-tenant attribution. Networking is local — no TPROXY/policy-routing needed.

### Prior art & realism

Model A is more precedented than it looks. Its defining move — intercept *outside* the VM, at the host's tap device — is the documented, recommended Firecracker pattern, not a novel invention. Firecracker performs no traffic filtering itself and its docs state that all guest egress "should be filtered at the host level," at the kernel-owned tap end of the VM's NIC that the guest cannot see or address. AWS Lambda/Fargate are the existence proof at scale; Teleport's agent runtime uses Firecracker VMs with a policy-controlled egress proxy on exactly this substrate.

Decompose Model A and each building block has separate, strong prior art:

1. **Host-side capture of a sandbox VM's egress** — tried and trusted (Firecracker + host tap + `iptables`/`physdev` default-deny; Lambda/Fargate; Teleport). Adopt without hesitation.
2. **Credential injection at egress for agents** — a real, shipping category as of 2026, not a research idea: Cloudflare Sandbox "Outbound Workers" (every outbound request crosses a Worker that injects the real key; the sandbox holds only a short-lived JWT/dummy), Infisical `agent-vault` (HTTP credential proxy that swaps a dummy `ANTHROPIC_API_KEY` for the real one), LangChain's sandbox auth proxy. The *purpose* is validated by multiple independent implementations. The broader "client never holds the long-lived secret" principle is also proven by HashiCorp Boundary, Teleport, and oauth2-proxy.
3. **Fully transparent TLS MITM of arbitrary HTTPS upstreams** — this is the one genuinely hard part, and the agent tooling above mostly *avoids* it: Cloudflare hooks the runtime fetch layer, Infisical uses an explicit `HTTP_PROXY`, and the dummy-token swap lets the proxy match a known sentinel instead of parsing every auth scheme. The tech that does blanket transparent MITM is corporate TLS inspection (Zscaler, Palo Alto) and `mitmproxy`/Squid `ssl-bump` — mature, but carrying exactly the trust-store, pinning, and per-runtime-CA fragility flagged in the primary Edits.

**Recommended default for Model A — explicit proxy + default-deny, not blanket MITM.** Keep Model A's placement (proxy, real creds, and CA private key all on the host, never in the VM), but:

- Have the VM reach the host proxy via explicit `HTTP_PROXY`/`HTTPS_PROXY` + an injected CA for the `CONNECT` tunnel, rather than transparent `iptables`/TPROXY capture. This is the Infisical/corporate-proxy pattern — far less plumbing, honored by nearly every SDK and language runtime.
- Use the **dummy-credential swap** (Cloudflare/Infisical style). This doubles as the fix for the SDK-preflight problem: the sandbox holds a sentinel that satisfies client-side "key must be set" checks, and the proxy replaces it with the real value.
- Back it with **default-deny egress at the host firewall.** This removes the standard objection to explicit proxies ("apps can ignore `HTTP_PROXY`"): if the only permitted egress route is the proxy, an app that ignores the env var doesn't bypass anything — it just fails to connect. This buys transparent mode's non-bypassability with explicit mode's simplicity.
- Reserve **full transparent `iptables`/TPROXY MITM** only for the residual case of third-party binaries with hardcoded URLs that ignore proxy env — and even those stay contained by the default-deny firewall.

Net: commit to Model A's *architecture* (inject on the host, outside the VM trust domain) — it is well-precedented. Treat Model A's most aggressive *mechanism* (universal transparent TLS MITM) as optional/last-resort rather than the default.

### Summary

| Concern | Model A (host-side) | Model B (in-VM) |
|---|---|---|
| Credential values in VM | never | yes (Envoy memory) |
| CA private key in VM | never | yes |
| Bypassable by VM-root | no (boundary outside VM) | yes — requires de-privileged workload |
| Interception mechanism | recommended: explicit `HTTP_PROXY` + CA + host default-deny; transparent `PREROUTING`+TPROXY only for proxy-ignoring binaries | in-VM `OUTPUT` + REDIRECT |
| Identity attribution | net-new (VM → user mapping) | trivial (one VM = one user) |
| Secret-store auth from VM | n/a (never in VM) | per-VM bootstrap credential required |
| CA public cert + trust env vars in VM | required | required |

### What works over encrypted traffic (and what fails closed)

This model does **not** work on "any encrypted traffic." It works on TLS-wrapped **HTTP** that the proxy can decrypt (VM trusts the injected CA, upstream is not cert-pinned) **and** where the credential is either a header the proxy can set or a signature the proxy can recompute from the plaintext request. The proxy must be able to answer yes to both: (1) *can I decrypt it?* and (2) *can I express the credential at a layer I control?* This sharpens the existing "Compatibility Classes" section for the host/VM topology.

- **Simple header injection/swap — works out of the box.** Bearer, API key, Basic, OAuth2 (OAuth2 also needs the proxy to run the token acquisition/refresh lifecycle). Proxy terminates TLS, swaps the sentinel for the real value, re-originates.
- **AWS SigV4 / HMAC body signing — works, but only as a re-signing proxy, never as header injection.** The `Authorization` value is a signature computed over the canonical request *including a hash of the body*, so it cannot be pre-minted and pasted. The VM SDK is given **dummy** credentials (it refuses to build a request without some, and signs with them); the proxy **discards that signature and re-signs the final request from scratch** with the real credentials (host-only), then forwards with no further mutation (any downstream change invalidates the signature). Tried-and-trusted piece: Envoy's `aws_request_signing` HTTP filter does exactly this. Sharp edges: the proxy must **buffer the whole body** to hash it, so streaming/chunked uploads need AWS chunked signing (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`), and S3 has its own quirks. This is a per-service signer, not a config line next to `bearer`.
- **mTLS — works, and is the ideal fit, with one caveat.** On the proxy→upstream leg the proxy presents the **client certificate** and proves possession of its key; the VM never holds it — the client-cert key is just another host-only secret. Fails only if the *application* must prove key possession **end-to-end** (channel/token binding, or an app that insists on its own upstream handshake) — but that requires the app to hold the key, which contradicts the security goal, so it is not a real loss.
- **Fails closed / needs a different mechanism:**
  - **Certificate pinning** (upstream) — VM rejects the proxy's MITM cert; connection fails, by design. Check third-party binaries.
  - **App-layer / end-to-end body encryption** — proxy sees ciphertext even after TLS termination; cannot operate on it. Protocol-specific or unsupported.
  - **Non-HTTP protocols** (Postgres, MySQL, Redis, SSH, SMTP, AMQP, raw TCP) — no HTTP header to inject; auth is in the protocol handshake. Requires a **protocol-aware proxy** (à la PgBouncer IAM auth, HashiCorp Boundary, Teleport) or is blocked. gRPC is the exception — it is HTTP/2, so metadata injection works if the proxy terminates h2.
  - **QUIC / HTTP/3 (UDP)** — not caught by TCP capture or `CONNECT`; block UDP/443 to force TCP fallback.

**Why "fails" is acceptable here — default-deny turns every gap into a refusal, not a bypass.** Because the host runs default-deny egress, an unsupported case (pinned cert, non-HTTP protocol with no proxy built, QUIC attempt) degrades to *no connection* — the credential is never exposed and traffic never leaks; the workload just gets an error. The corollary: **the set of things that work is exactly the set you have explicitly built a tier for** — bearer/key/basic/OAuth2 out of the box; SigV4/HMAC/mTLS/protocol-X only once each is implemented as its own tier (see Recommended MVP taxonomy).

| Auth / traffic type | Status in this model | Mechanism |
|---|---|---|
| Bearer / API key / Basic | works | header set/swap after TLS termination |
| OAuth2 | works | proxy runs token lifecycle + injects |
| gRPC (bearer in metadata) | works | h2 termination + metadata injection |
| AWS SigV4 / HMAC body signing | works (harder) | proxy re-signs final request; dummy creds in VM; buffers body |
| mTLS (proxy owns client cert) | works | proxy presents client cert on upstream leg; key stays on host |
| mTLS (app must hold key e2e) | unsupported | contradicts goal — app would hold the secret |
| Certificate pinning (upstream) | fails closed | VM rejects MITM cert; no workaround |
| App-layer body encryption | unsupported | proxy sees ciphertext post-TLS |
| Non-HTTP (Postgres/Redis/SSH/SMTP…) | needs protocol proxy / blocked | no HTTP header; protocol-aware handler required |
| QUIC / HTTP-3 (UDP) | blocked | not intercepted; force TCP fallback |

## Recommended MVP

Start narrow:

- HTTP/HTTPS only
- bearer/API-key/header injection only
- no wildcard egress
- no SigV4/HMAC/mTLS/non-HTTP
- non-root workloads with dropped capabilities
- centralized access logs
- self-service credential connect/revoke UI

Then add harder classes explicitly as separate implementations:

```text
bearer_header          simple injection
api_key_header         simple injection
oauth2_token           token acquisition + injection
sigv4_signing_proxy    service-specific signer
mtls_upstream          Envoy-owned client cert
protocol_proxy         protocol-specific implementation
unsupported            fail closed
```
