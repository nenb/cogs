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

## Deliberately absent

ADR 0096 and the later image-source changes now provide `src/main.ts`, fail-closed production composition, bounded API bind/shutdown persistence wiring, the canonical Basic proxy capability, worker-owned Envoy process composition, production worker image source, and the Kata guest image/entrypoint source. Egress startup uses retained lifecycle ownership: an abort waits for or subsequently closes any manager that resolves late, so a late Envoy cannot escape rollback ownership. The process entrypoint arms the 31-second hard-exit deadline for signals, startup failure, spontaneous runtime loss, and shutdown failure; it clears that timer only after cleanup completes without uncertainty. The worker dependency stage also replaces Pi 0.80.6's shrinkwrap-retained `brace-expansion` 5.0.6 and `undici` 8.5.0 with the root lock's exact authenticated 5.0.9 and 8.9.0 bytes, verifies both expected vulnerable inputs and fixed outputs, and copies only the remediated dependency tree into the final image. Those are locally tested source contracts only; they are not runtime, publication, deployment, or isolation observations; a local image build verifies construction but does not promote readiness.

The following remain deliberately absent:

- production runtime-material provisioning and a controller that creates the worker/sandbox pair;
- static deployment materialization (the Helm chart remains NOTES-only with zero submitted manifests);
- any runtime qualification inferred from Docker builds, scans, SBOMs, signatures, publication, or registry readback;
- a mutable release alias, production promotion, or executable provider route; and
- Linux/Kata/KVM, Kubernetes, CNI, storage, network, and end-to-end runtime qualification.

Protected-main run `30852317459` and its independent review now supply exact immutable worker/sandbox identities to readiness v3, so `RELEASE_IMAGE_SET_ABSENT` and the placeholders are removed. The image-source revision remains separately bound from later readiness metadata. The later OpenBao v2.6.1 retirement adds `OPENBAO_FIXED_RELEASE_IMAGE_ABSENT`; `NO_EXECUTABLE_PROVIDER_ROUTE` and every false runtime/provider/Kubernetes/cloud/Stage 4 exit/production/release claim remain unchanged.
