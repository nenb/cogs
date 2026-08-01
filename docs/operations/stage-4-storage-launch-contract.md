# Stage 4 local/static storage and session-launch contract

This issue #355 slice defines a strict, provider-free object graph. It is not a launcher, Kubernetes producer, StorageClass/PVC, lease service, RuntimeClass discovery mechanism, or cleanup observer. It performs no filesystem, process, network, environment, Kubernetes, cloud, OpenTofu, Helm install/apply, or external-model operation.

The contracts are:

- [`schemas/stage4-storage-launch-contract-v1.json`](../../schemas/stage4-storage-launch-contract-v1.json);
- [`schemas/stage4-storage-launch-verdict-v1.json`](../../schemas/stage4-storage-launch-verdict-v1.json); and
- the pure classifier in [`scripts/stage4-storage-launch-contract.ts`](../../scripts/stage4-storage-launch-contract.ts).

Every verdict fixes qualification, campaign authorization, cloud execution, Kubernetes execution, provider truth, Stage 4 exit, and release eligibility to `false`. `admissible-static-graph` means only that supplied local metadata matches this contract. `cleanup-order-complete` means only that a supplied semantic graph has the fixed terminal shape; it is not cleanup or zero-inventory evidence.

## Separate durable storage roles

| Role | Exact contract | Visibility | Retention |
|---|---|---|---|
| Project workspace | 20 GiB (`21474836480` bytes), CSI block-backed, `Filesystem`, `ReadWriteOncePod`, `WaitForFirstConsumer`, `Retain` | Kata sandbox only; never mounted by the trusted worker/proxy | retained across session end until explicit workspace deletion |
| Trusted Pi session state | 5 GiB (`5368709120` bytes), `Filesystem`, `ReadWriteOncePod`, `WaitForFirstConsumer`, `Retain` | trusted worker only; never visible to the sandbox | 30 days (`2592000` seconds) after session close |

The StorageClasses must be distinct. These are role and lifecycle requirements, not claims about any installed CSI driver or observed reclaim behavior. A future materializer must map them without silently substituting EFS/RWX, raw block mode, immediate binding, automatic reclaim, a shared mount, or another retention policy. Any mode or role drift is denied.

## Exclusive writer lease

One workspace has at most one writer. The lease is bound to the immutable launch-document SHA-256 and requires a monotonic fencing token. Expiry alone never authorizes takeover. A second writer, wrong holder, unknown lease state, premature release, detach uncertainty, or cleanup ambiguity returns `preserve-uncertain`; the workspace, attachments, and lease must be preserved for a separately authorized recovery path.

The local state shapes are:

```text
active:
  worker/proxy present + sandbox present + both volumes attached + fenced lease held

cleanup-requested:
  removals requested + detaches requested + lease release requested

complete (semantic ordering only):
  resources removed + both attachments detached + lease released

any uncertain or contradictory observation:
  preserve-uncertain; no takeover, reuse, deletion, or success promotion
```

Uncertainty is sticky and an explicit marker in a safely bounded descriptor snapshot is evaluated before version and strict-schema admission; contradictory lifecycle states are evaluated before later semantic checks. Once cleanup is uncertain, host-key mismatch, RuntimeClass failure, document staleness/digest mismatch, resource cardinality/binding failure, malformed domain identity references, unknown admission fields, identity persistence, wrong storage mode, or concurrent-writer metadata cannot demote the result to ordinary rejection. Every `preserve-uncertain` verdict explicitly fixes state, resources, attachments, and workspace lease to `preserve`. Resolution belongs only to a separate authority. This classifier has no override or recovery operation.

## One session object graph

Exactly one trusted resource contains exactly `worker` and `proxy`. Exactly one separate Kata sandbox resource contains exactly `sandbox`, names `kata-qemu-cogs`, has no trusted sidecar, mounts only the workspace, and cannot see trusted session state. The trusted resource mounts only trusted session state and never the untrusted workspace.

The immutable launch-document metadata contains exactly its version, session ID, workspace ID, trusted-resource ID, sandbox-resource ID, both storage roles, RuntimeClass name, source-revision SHA-256, and launch-nonce SHA-256. The classifier derives `document_sha256` from canonical metadata under the domain `cogs.stage4/immutable-session-launch-document/v1` and rejects a supplied mismatch. Both resources and the lease must reproduce the metadata bindings and derived document digest. Mutating metadata, session/workspace/resource references, or resource bindings while retaining the old digest cannot pass.

Session, workspace, and resource IDs are not arbitrary opaque strings. They are kind-specific digest references (`cogs.<kind>/v1:sha256:<lowercase digest>`), preventing token/credential-shaped values and cross-kind substitution. Their preimages and provenance remain caller claims: domain-shaped references do not authenticate an issuer, launch, resource, or observation.

RuntimeClass resolution is a bounded caller assertion. `present-static-assertion` does not establish cluster truth; `missing`, a wrong name, or any runc/TCG fallback denies admission. The checked NIC v0.11.0 contract remains independently `blocked-missing-capability` because it cannot preserve custom launch-template ID/version or nested-virtualization CPU options. Issue #355 neither depends on nor changes that provider-source result.

## Immutable and ephemeral identity boundary

The graph carries no SSH private/public key, host-key fingerprint, proxy capability value, secret-store handle, endpoint credential, or identity payload. It records only policy states:

- SSH host-key pin is provisioned a priori through an out-of-band path;
- exact match is required; missing/mismatch denies with no TOFU or automatic update;
- the immutable document is admitted exactly once; stale or replayed documents deny;
- ephemeral SSH and proxy identities exist only in future launcher memory or bounded tmpfs;
- identity material is forbidden in Helm values, ConfigMaps, durable reports, and sandbox secret-store handles.

The Helm NOTES-only ConfigMap source shape contains only fixed policy labels and `ABSENT_FUTURE_TRUSTED_LAUNCHER_ONLY`; it contains no launch document or ephemeral identity value.

## Bounded pure input

Canonical JSON input is limited to 128 KiB including the terminal LF, 512 snapshotted nodes, depth 16, 2048 UTF-8 bytes per string, 256 UTF-8 bytes per property key, 64 properties per object, and one resource per role. Key length/count, depth, node count, and aggregate canonical-byte budget are enforced during the descriptor snapshot before canonicalization or hashing. Oversized unknown keys therefore return a null graph digest and `STAGE4_BOUNDED_IO_VIOLATION`.

Every object/function Proxy is detected recursively with `util.types.isProxy` before `Array.isArray`, prototype, own-key, or descriptor reflection; transparent and hostile Proxy traps are never executed. Unknown fields, accessors, sparse/extended arrays, symbol keys, non-plain prototypes, unsafe numbers, malformed UTF-8/JSON, UTF-8 BOM, noncanonical key/whitespace/newline representations, missing or extra terminal LF, and bound violations fail closed. Getter bodies are never invoked. A bound violation preserves state rather than authorizing cleanup or retry.

The validator reads no path and exposes no callback, command, target, process, launcher, provider, or Kubernetes client surface. Future real admission, lease acquisition, host-key verification, RuntimeClass discovery, attachment observation, and cleanup require separately approved implementations and evidence authorities.
