# Production runtime foundation boundary

ADR 0095 adds only the strict inputs needed by a future production worker composition. It does not start a worker or establish deployment/runtime authority.

## Runtime document

`schemas/runtime-v1alpha1.json` defines one canonical `cogs.runtime/v1alpha1` document. `src/runtime/config.ts` safely snapshots direct objects and parses canonical UTF-8 JSON bytes with a final LF. The contract is deliberately closed:

- release profile is exactly `api-key-only`;
- launch, API bearer, projected JWT, proxy capability, Envoy, tmpfs, WAL, session, and skill paths are fixed; the shared proxy-capability grammar is base64url without padding, 32 through 128 characters;
- API and egress ports are bounded and distinct;
- OpenBao is canonical HTTPS with bounded Kubernetes-auth, KV, and PKI names;
- projected JWT and OpenBao client-token TTL bounds are exactly 600 seconds;
- OTLP is the implemented HTTP/JSON protocol with exact HTTPS `/v1/traces`, `/v1/metrics`, and `/v1/logs` endpoints;
- revocation, completion, session, and shutdown bounds are explicit.

The validator applies no defaults, coercion, field removal, or ambient environment discovery. Unknown fields, noncanonical URL spelling, HTTP, URL credentials, query/fragment data, mutable paths, OAuth profiles, unsupported OTLP protocols, getters, Proxies, sparse arrays, symbols, non-plain prototypes, malformed UTF-8, BOM, noncanonical JSON bytes, and bound violations fail closed.

## Trusted file capture

`src/runtime/trusted-files.ts` provides callback-scoped capture for already provisioned files. Callers must supply exact accepted UIDs, GIDs, modes, and byte bounds. Capture:

1. validates a canonical absolute path and exact options without invoking getters or Proxy traps;
2. opens and retains every parent directory with `O_DIRECTORY|O_NOFOLLOW`;
3. compares path and descriptor generations;
4. opens the final file with `O_NOFOLLOW` and requires one regular link;
5. requires exact owner, group, mode, and byte bounds;
6. performs a bounded descriptor read and rejects short or additional bytes;
7. revalidates final and parent path/descriptor generations;
8. closes every descriptor before invoking the consumer;
9. exposes bytes only through the awaited callback and zeros them on every return or failure; and
10. emits only `COGS_TRUSTED_FILE_INVALID` / `trusted file unavailable` on failure.

The helper does not create, chmod, chown, rename, delete, discover, or recover material. Provisioning and ownership remain external.

## OpenBao Kubernetes-workload identity

`src/auth/openbao-workload-identity.ts` implements the existing `OpenBaoIdentityPort`. Each `withToken` call:

1. captures and rereads the projected JWT, observing external rotation;
2. validates an exact three-segment base64url JWT shape;
3. sends one bounded HTTPS request to `/v1/auth/<mount>/login` with `{role,jwt}`;
4. disables redirects and applies caller abort plus an independent login timeout;
5. bounds status, content type, declared length, streamed bytes, UTF-8, JSON, envelope fields, token type, token bytes, and lease TTL;
6. invokes the token callback exactly once and awaits it; and
7. clears local JWT/body/token references and returns only a generic redacted error on failure.

No OpenBao token appears in the runtime or launch document. There is no HTTP development option, static-token option, environment source, token cache, renewal loop, Kubernetes API call, SDK, OAuth path, or fallback.

## Production sandbox SSH identity

Production composition authenticates SSH/SFTP exactly as `root`, matching the sandbox image's root-only `sshd`. This intentionally preserves DESIGN's guest-root semantics; there is no `cogs` guest account or non-root fallback, and the existing public-key-only, forwarding, tunnel, password, and PAM restrictions remain unchanged.

## Authenticated Pi turn deadline

Every current runnable launch document supplies `turn_timeout_seconds` explicitly. The shared authenticated launch-to-Pi boundary derives the exact millisecond turn deadline from that validated value; production composition cannot override or omit it. The deadline starts with the original prompt and covers Git setup, model/retry/compaction work, queued steering/follow-up, tools, durable persistence, and Git settlement. Queued input never refreshes it, and monotonic expiry suppresses late success even if timer delivery is delayed. The required 60-second margin over the tool limit is minimum configured headroom, not reserved time or a guarantee that a late tool receives its full allowance.

Tool-adapter timing remains separate. In particular, the SFTP operation deadline does not include permit acquisition or channel opening, and cancellation, channel close, cleanup, and actual retirement retain their independent bounds. No deadline proves retirement.

## Deliberately absent

ADR 0096 and the later image-source changes now provide `src/main.ts`, fail-closed production composition, bounded API bind/shutdown persistence wiring, the canonical Basic proxy capability, worker-owned Envoy process composition, production worker image source, and the Kata guest image/entrypoint source. Egress startup uses retained lifecycle ownership: an abort waits for or subsequently closes any manager that resolves late, so a late Envoy cannot escape rollback ownership. The process entrypoint arms the 31-second hard-exit deadline for signals, startup failure, spontaneous runtime loss, and shutdown failure; it clears that timer only after cleanup completes without uncertainty. The worker dependency stage installs exact Pi 0.84.2, verifies the authenticated shrinkwrap's fixed nested `brace-expansion` 5.0.9, `protobufjs` 7.6.5, and `undici` 8.9.0 bytes, and copies only that reviewed dependency tree into the final image. Those are locally tested source contracts only; they are not runtime, publication, deployment, or isolation observations; a local image build verifies construction but does not promote readiness.

The following remain deliberately absent:

- production runtime-material provisioning and a controller that creates the worker/sandbox pair;
- static deployment materialization (the Helm chart remains NOTES-only with zero submitted manifests);
- any runtime qualification inferred from Docker builds, scans, SBOMs, signatures, publication, or registry readback;
- a mutable release alias, production promotion, or executable provider route; and
- Linux/Kata/KVM, Kubernetes, CNI, storage, network, and end-to-end runtime qualification.

Protected-main run `31856469035` and its independent review bind the Pi 0.84.2 source to exact current worker/sandbox identities, so readiness v5 removes `RELEASE_IMAGE_SET_ABSENT`. The image-source revision remains separately bound from later readiness metadata, and the earlier run `30852317459` remains historical. OpenBao v2.6.1 remains retired, so `OPENBAO_FIXED_RELEASE_IMAGE_ABSENT`; `NO_EXECUTABLE_PROVIDER_ROUTE`; and every false runtime/provider/Kubernetes/cloud/Stage 4 exit/production/release claim remain unchanged.

## ADR0333/0334 functional product harness

`dev/product-test/runner.ts`, `snapshot-owner.ts`, and `host-custody.py` provide the local functional composition contract. This is **not execution authorization or Linux qualification**. No Docker, KVM, image build, provider, cloud, AWS, workflow, or credential operation was performed to validate this implementation. The retired ordinary OpenBao launcher is neither imported nor changed.

After the separate reviewed execution gate, use a **fresh protected Linux/amd64 runner**, root supervisor, local Docker socket, cgroup-v2 **cgroupfs** driver, overlay2, enabled memory/CPU/PID controllers, Python with pidfds/`renameat2`, loop/ext4 utilities, OpenSSL and Ed25519 `ssh-keygen`. An externally provisioned root-owned `0700` `/var/lib/cogs-product-test` parent and exact locally preloaded sandbox, stock-worker, and candidate-worker image IDs are prerequisites. Missing prerequisites fail, not skip. There must be no foreign containers, sensitive workspace or unrelated workload; the protected-runner restriction is an operator attestation, not host-workload discovery authority.

The fixed in-memory candidate Dockerfile is printed by `node --experimental-transform-types dev/product-test/runner.ts --dockerfile`. It copies candidate source onto the pinned stock worker using `PINNED_WORKER`; construction/preloading is a separate, later, networkless operation. No release image definition or workflow is changed. The harness itself never builds or pulls images. On the reviewed runner, the entry contract is `node --experimental-transform-types dev/product-test/runner.ts --protected-linux /root/restrictions.json <candidate-sha>` with credential/agent/Docker/Node override environment absent. Run empty and nonempty skill profiles on separate fresh runners.

The protected, networkless build must independently retain `/var/lib/cogs-product-test/build-receipt.json` (root-owned, single-link, mode `0400`). Its closed fields are `baseline`, `candidate`, `tree`, `source`, `recipe`, `sandbox_image`, `worker_image`, `stock_worker_image`: exact commit/tree IDs, SHA-256 of canonical sorted copied-path to `{digest, mode}` inventory, SHA-256 of the printed Dockerfile, and exact image IDs. The issuer must bind the unchanged production sandbox and stock-worker builds; copying caller assertions is not a build receipt. The harness verifies the clean checkout, unchanged production build inputs, worker layer ancestry, and stopped-container source bytes before candidate start. Image and created-container environments have a closed value allowlist; inherited Node hooks, credentials and TLS overrides fail before start. Evidence carries the verified provenance.

Custody durably records acquisition intent and observed root/cgroup/backing-file/loop/mount identities, and retains a generation lock. On interruption, the existing Python entrypoint accepts one JSON line with `generation`, `seconds` (60..600), and `cleanup_only: true`; it locks and reopens that generation's control journal, never admission or work. Replaced identities, lost unreceipted container IDs, and unresolved effects remain cleanup-required rather than being adopted by name. This is a recovery contract, not permission to execute it outside the reviewed runner gate.

History admission synchronously vetoes forbidden properties before native writes, with host-owned admission hashes/node counts reconciled against retained JSONL before history requests. Pass requires delivered-event agreement, successful completion/WAL/upstream correlation, typed telemetry exports and accounting, exact Git/notes and export manifests, and a closed retained inventory. Evidence is checked again after all container writers retire, while storage remains mounted. Checkpoints are not enabled by this fixed scenario; unexpected checkpoint residue fails.

The restriction file is root-owned, single-link, no-follow captured, mode `0400`, canonical sorted UTF-8 JSON plus LF. Its closed fields are: `version=cogs.product-restrictions/v1`, exact Q `baseline`, externally reviewed `candidate`, `owner=repository-owner`, millisecond `expires` (within one day and beyond the entire test), `profile=functional-only-protected-linux-docker/v1`, `breach=fail-and-settle-exact`, `findings=[4,5,6,8,9,10,14]`, `seconds` in 60..600, `skills=empty|nonempty`, three distinct exact `sha256:` image IDs (`sandbox_image`, `worker_image`, `stock_worker_image`), and `fresh_protected_runner=true`. It is generation admission, not production permission. Runtime/launch validation and exactly one fixed local integration precede acquisition; the launch schema remains weaker than production admission.

Custody is an independent root process outside the candidate cgroup. It retains exclusive intents and exact container receipts; a lost create/start response never authorizes name-based discovery or deletion. Helpers stop before exec and enter the subordinate cgroup. Both containers have read-only rootfs, no log driver, no privilege, default seccomp, no-new-privileges, exact private bind mounts, no source/containing-directory aliases, and memory/swap/CPU/PID limits. PID/pidfd, image, mount namespace, live RO flags, device/inode, capabilities and cgroup limits are checked before releasing the inert worker. Unix kernel-peer authentication, nonce/sequence checks and heartbeats bind the gate and one-time snapshot consumer lease. Control loss/deadline fails closed; it never proves retirement.

Publication uses a 32 MiB loop filesystem and descriptor-relative paired staging, canonical retained bundle verification/discovery, bounded inventories, bottom-up fsync, no-replace rename, parent fsync and readback. Sandbox mounts only exact shared/user digest subtrees RO. Worker gets separate RO OCI/user sources, runtime/launch, synthetic secrets and lease mounts; private store, agent/session JSONL and audit WAL reside in the bounded 512 MiB state filesystem. Workspace is a separate 2 GiB filesystem, RW only in sandbox; all remaining writable locations are explicitly bounded tmpfs. Stock trust is read by an exact-ID networkless utility; only the synthetic Envoy CA is appended. A distinct telemetry CA is fixed through `NODE_EXTRA_CA_CERTS` before Node initialization. `/etc/hosts` fixes `fixture.cogs.test`; Envoy's existing exact DNS-SAN validation and trust-file authority remain intact.

The real production compose/Pi/SSH/SFTP/lifecycle/API/Envoy/ext-authz/WAL/default telemetry paths run with frozen, closed synthetic identity/model/PKI/credential ports; only model output is deterministic. The fixed Python proxy client consumes the authenticated SSH-session `HTTPS_PROXY`, not the bootstrap endpoint, rejects missing environment before connecting, checks wrong capability rejection, and requires one authenticated upstream request plus WAL evidence. The client causally waits for SSE headers, permits no reconnect, exercises normal/oversized/next turns, bounded history and byte-exact fragments, and waits for settled shutdown. Host pre-publication counters enforce 48 events/16 turns; history is bounded to 25 metadata entries/2048 source nodes. No replay, configurable tool-limit, BOM edit, recycle, arbitrary-property, long-history or rootfs-acquisition claim follows.

Normal settlement closes worker before sandbox, proves exact-ID removal/pidfd exit and cgroup emptiness, then revokes channels and unmounts snapshots/storage. Published snapshot storage and sealed synthetic key/token files are removed only after container retirement; workspace/state loop images, Git/checkpoints, JSONL, WAL, documents and generation journals remain for inspection. These retained images require separately reviewed read-only inspection/disposal, not fixture `rm`, Docker prune or broad EXIT cleanup. Failed work stays failed after certain cleanup; partial/uncertain custody and `cleanup-required` remain sticky. Exact pre/post Docker inventory and the 256 MiB daemon-disk delta are observational failure thresholds, **not peak daemon-storage quotas**; fixed runner disk and workflow deadline remain external availability backstops.

Portable coverage uses fake custody/Docker/syscalls and temporary generated skill sources, plus existing real loopback telemetry tests. It does not prove actual Linux Docker mount behavior, cgroup driver support, authenticated SSH capability-removal measurements, live Envoy CONNECT/TLS, production HTTPS export, or clean physical residue. Those tests, fresh-runner feedback, deterministic readiness regeneration, full local checks and independent implementation reviews remain required before any authoritative pass/finding closure. No historical H/G/Q evidence is borrowed.
