# Stage 4 static storage and launch-contract evidence

## Scope

- Issue: #355.
- Authority: `local-static-storage-launch-classifier`.
- Cloud/provider/Kubernetes execution: none.
- Actual launcher, process, lease, storage, RuntimeClass, host-key, or cleanup observation: none.
- Qualified / Stage 4 exit / release eligible: false.

This report records local schema, pure-classifier, object-graph, Helm NOTES-only, and documentation coverage. It is not EKS, NIC, CSI, Kata, Kubernetes, provider, deployment, cleanup, or release evidence. No provider/AWS/OpenTofu/SSM operation, `kubectl`, Helm install/apply, Kubernetes API call, external model call, launcher, or child process was used by the #355 classifier.

## Contract coverage

The strict schemas and pure deterministic classifier establish the expected local shape for:

1. a 20 GiB CSI block-backed `Filesystem` / `ReadWriteOncePod` / `WaitForFirstConsumer` / `Retain` sandbox-only workspace retained until explicit workspace deletion;
2. a distinct 5 GiB `Filesystem` / `ReadWriteOncePod` / `WaitForFirstConsumer` / `Retain` trusted-worker-only Pi session-state role retained for 30 days after close;
3. a fenced one-writer workspace lease where expiry never authorizes takeover;
4. exactly one trusted worker/proxy resource and one separate `kata-qemu-cogs` sandbox bound to one immutable, single-admission launch-document digest;
5. a priori SSH host-key matching with no TOFU/update and denial on missing/mismatch;
6. no durable SSH/proxy identity material and no sandbox secret-store handle;
7. active, cleanup-requested, complete-semantic, and sticky uncertainty lifecycle shapes; and
8. canonical byte and hostile object-graph bounds.

Positive tests cover deterministic digest binding and the three non-uncertain lifecycle results. Negative tests cover wrong size/access/volume/medium/owner/retention, shared mounts, concurrent writers, wrong lease holder, lease expiry takeover, missing/wrong RuntimeClass, runc substitution, host-key mismatch/missing, stale/replayed documents, wrong session/document bindings, duplicate/missing resources, trusted sidecars, durable identity destinations, cleanup contradictions, malformed/noncanonical/oversized input, getters, proxies, symbols, sparse arrays, and non-plain prototypes.

## Helm boundary

The Helm chart remains default-disabled and NOTES-only. Normal `helm template` output remains zero submitted manifests even when the static source shapes are enabled. The warning-bounded ConfigMap source shape records fixed storage-role/retention/lease policy labels only. It contains no launch document, key, fingerprint, capability value, secret-store handle, or report identity payload. PVCs, RuntimeClass, Pods, and all launch resources remain absent from submitted manifests.

## Independent NIC blocker

The local NIC v0.11.0 classifier remains `blocked-missing-capability`: its pinned source cannot express custom launch-template ID/version or `CpuOptions.NestedVirtualization`, and the EKS node-image pin remains unresolved. The #355 classifier performs no provider/source discovery and fixes `provider_truth_observed=false`; its local shape cannot bypass, resolve, depend on, or promote the NIC result.

## Remaining qualification

A future separately approved authority must implement and observe actual StorageClasses/CSI modes, PVC retention/deletion, fencing and concurrent-writer denial, RuntimeClass existence and no fallback, one exact resource pair, immutable launch admission and replay storage, SSH host-key verification, ephemeral identity custody, volume attach/detach, cleanup ordering, and independent zero inventory. Local acceptance of this contract establishes none of those runtime facts.
