# ADR 0094: Preserve NOTES-only Helm and add a local static manifest route

- Status: Accepted
- Date: 2026-08-02
- Decision owner: Nick Byrne
- Accepted by: Nick Byrne through the explicit implementation instruction for `feat/nic-static-route`

## Context

The Stage 4 Helm chart deliberately contains Kubernetes source shapes only behind `templates/NOTES.txt`. Normal lint, install-like rendering, upgrades, API-version injection, and schema-skipped rendering submit zero manifests. That boundary prevents an unfinished chart from being mistaken for deployment authority.

Cogs now accepts the exact personal-fork source closure at NIC commit `53b1a791ed1ff394969e0aeaa6379be955244b62` and module commit `c3017c0e15b538cd4e04c0786809a861ea82c621`. Those commits can preserve an external launch-template ID and explicit integer version and require an operator nested-virtualization attestation. They do not inspect the launch template, call AWS, or establish provider truth.

A later campaign needs deterministic manifest and NIC configuration bytes to review and bind before any separately authorized executor exists. Turning the chart into an installable chart would collapse static preparation into an implicit deployment route.

## Decision

1. `deploy/helm/cogs` remains NOTES-only and emits zero Kubernetes manifests in every normal Helm rendering mode.
2. A separate bounded local executable may authenticate the chart and pinned Helm binary, render only with `--dry-run=client` and an absent kubeconfig, extract the warning-bounded NOTES payload from a private review wrapper, and write deterministic handoff files.
3. The executable accepts only one strict canonical request and one new output directory. It writes only `manifests.yaml`, `nic-config.yaml`, and `receipt.json`.
4. The route may materialize bytes but may not install, upgrade, apply, validate against, discover, contact, or authenticate to Kubernetes or a cloud/provider API.
5. The receipt always fixes deployment execution, apply, Kubernetes client/execution, provider execution/truth, cloud execution, campaign authorization, Stage 4 exit, and release eligibility to false.
6. NIC v2 capability means only source-level configuration preservation plus operator attestation. Launch-template contents, reconciliation, node image, KVM, runtime, and scheduler state remain unobserved.
7. The historical NIC v1 assessment remains immutable. The accepted personal-fork closure is a separate v2 authority.

## Consequences

- The materialized files are suitable for digest-bound review and later handoff, but are not instructions or authority to deploy.
- A future executor requires a separate ADR and exact campaign approval after all retained blockers close.
- No `kubectl`, Kubernetes client library, AWS SDK, OpenTofu, Terraform, Helm install/upgrade, shell, or network route belongs in the static materializer.
- Placeholder images in the synthetic fixture remain non-release inputs; image and runtime closure are handled separately.

## Rejected alternatives

### Emit manifests from the existing chart

Rejected. It removes the mechanically tested zero-manifest boundary and makes ordinary Helm commands look deployable.

### Add an apply helper beside the renderer

Rejected. A local byte materializer is not campaign authority, and adjacency would create an accidental execution path.

### Treat operator review as provider observation

Rejected. Both fork implementations explicitly describe the review and configured output as attestations without AWS lookup or verification.
