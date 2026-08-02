# Draft installation guide

This guide stops at local/static preparation. It does not install into a cluster and contains no provider operation or deployment target. Read the [runbook authority rules](README.md) first.

## Assumptions

- A future platform team will supply the daemon, authenticated user mapping, session scheduling, approved cluster-scoped Kata installation, CNI, CSI, OpenBao, and OTLP services that Cogs itself does not provide.
- A future installation will use synthetic data until a separate data-handling decision exists.
- Exact accounts, principals, regions, prices, quotas, images, node images, and campaign approval are absent today.

These assumptions are admission questions, not facts.

## Static contract facts

- The checked Helm chart is version `0.0.1` and is a NOTES-only scaffold that submits zero manifests. Enabled source shapes are unsafe and unqualified notes, not an installer.
- The offline package uses synthetic `.invalid` worker and sandbox image references. It contains no release image set or executable provider route.
- The sandbox contract requires `kata-qemu-cogs`, KVM only, and no `runc` or TCG fallback. Trusted worker/proxy and sandbox scheduling domains are disjoint.
- Workspace and trusted session state are distinct retained roles; see the [storage/launch contract](../stage-4-storage-launch-contract.md).
- The NIC source is blocked and the EKS AMI/image/kernel pin is unresolved; see the [NIC contract](../stage-4-nic-node-group-contract.md).

## Authoritative-local facts

- Node.js `22.22.2` is the checked local baseline.
- The accepted [Stage 3 Linux/KVM report](../../test-reports/stage-3-s3-09-linux-kvm-exit.md) is authoritative only for its exact local guest-root profile.
- The insecure container is functional-only. A macOS VM has no authoritative host-network/default-deny claim.

None of these facts proves cluster installation behavior.

## Future cloud evidence

A separately approved exact-revision campaign must establish, with real dependencies:

- exact source and image digests, node image/kernel, Kata/QEMU/containerd identity, and active KVM acceleration;
- actual RuntimeClass, CNI dual-stack default deny, CSI modes, OpenBao workload identity, OTLP, audit WAL, and scheduler separation;
- repeatable install, readiness, failure, and destroy behavior with independent inventory;
- the applicable S4-11 and [Stage 5 matrix](../stage-5-api-key-release-acceptance-matrix.md) evidence bindings.

No campaign is authorized by this list.

## Local/static preparation procedure

1. Confirm a clean checkout and Node.js `22.22.2` without introducing credentials or user data.
2. Read [prerequisites](prerequisites.md), [NIC configuration](nic-configuration.md), and the [platform matrix](platform-matrix.md). Stop on every unresolved item; do not substitute a component.
3. Perform dependency installation and repository checks only:

   ```bash
   npm ci --ignore-scripts
   npm run check
   ```

4. Inspect the non-deploying chart source locally only:

   ```bash
   helm lint deploy/helm/cogs
   helm template cogs deploy/helm/cogs
   ```

   The render submits nothing. Do not reinterpret rendered notes as deployable manifests.
5. Confirm the machine [runbook index](index.json) and all linked static contracts agree. A passing check closes only documentation/static consistency.
6. Record unresolved prerequisites and stop. Do not initialize a provider, contact a cluster, call an external model, or create a resource.

## Future installation hold points

A future authority must stop before each of these transitions: campaign request, cluster-scoped runtime change, identity/secret binding, first sandbox admission, first credentialed egress, and first persistent-data use. Each transition needs exact evidence, a named accountable principal, and a separately scoped approval. Missing or stale evidence leaves readiness false.
