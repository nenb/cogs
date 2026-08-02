# Stage 4 bounded local static manifest package

ADR 0094 preserves the Helm chart as NOTES-only and authorizes a separate local byte-materialization route. The route is suitable for later digest-bound handoff; it is not a deployment executor.

## Command

```bash
node scripts/stage4-static-manifest-package.ts \
  --request test/fixtures/stage4-static-manifest/valid-request-v1.json \
  --output /tmp/cogs-stage4-static-package
```

The output directory must not exist. The command writes exactly:

- `manifests.yaml` — the warning-bounded nine-object NOTES source payload;
- `nic-config.yaml` — the bounded active NIC v2 node-group handoff; and
- `receipt.json` — canonical digests and fixed non-authority claims.

The committed fixture is synthetic and contains placeholder worker/sandbox images. It is a deterministic test request, not release input.

## Local execution boundary

The executable authenticates the fixed Helm `v4.1.1` binary, complete chart inventory, active NIC v2 contract, and canonical request. It copies authenticated chart bytes into a private directory, runs strict lint, proves the original chart renders zero manifests, adds a private review wrapper, and invokes only local `helm template --dry-run=client` with an absent kubeconfig and bounded output.

It has no Kubernetes client library, API discovery, schema validation against a cluster, apply, install, upgrade, provider, cloud SDK, infrastructure tool, shell, arbitrary subprocess, or network route.

The request requires:

- exact Stage 4 values accepted by both the chart JSON Schema and template validation;
- one valid launch-template ID and native JSON integer version;
- operator attestation `nested_virtualization=enabled`; and
- the Cogs review requirements `core_count=1` and `threads_per_core=2` bound to that selection.

The generated NIC configuration intentionally carries only the nested-virtualization attestation accepted by the fork. Core/thread review remains in the request digest and receipt binding; it is not represented as a NIC/provider observation.

## Receipt authority

A valid receipt establishes deterministic local materialization only. It fixes all of these to false:

- deployment execution and apply route presence;
- Kubernetes client/execution;
- provider execution/truth;
- launch-template content observation;
- cloud execution and campaign authorization;
- Stage 4 exit and release eligibility.

No command in this repository consumes the package for deployment. Adding one requires a separate ADR, closure of retained campaign blockers, and exact one-attempt approval.
