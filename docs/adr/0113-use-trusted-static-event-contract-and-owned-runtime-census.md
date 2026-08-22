# ADR 0113: Use the trusted static-event contract and owned runtime census

- Status: Accepted under the owner's explicit issue-42 correction instruction
- Date: 2026-08-22
- Scope: One fail-closed correction generation for the consumed v4 no-KVM static-control event

## Context

Run `32563007701`, attempt 1, consumed the v4 static-control generation on exact protected `main` workflow head G8 `7f43d9acc5897b11b5d9794eb2e184767446aa48`, with reviewed implementation H8 `d05bbc5928bda9b6bd27da1c290b0238219fd185`. It completed with conclusion `failure` in the byte-identical first pre-checkout guard and emitted only the bounded diagnostic `EVENT_REJECTED`. Checkout, fixed-source materialization, immutable acquisition, candidate production, upload, KVM, QMP, runtime, task and guest-network effects were skipped. The run has zero artifacts and produced no source effect.

The v4 guard had already bound event name, repository, protected full ref, workflow ref, run ID, attempt, workflow head and exact reviewed H through GitHub's trusted default environment and `EXACT_IMPLEMENTATION_HEAD` through the typed workflow input. It then duplicated authorization by requiring one exact shape for `ref`, `repository.full_name` and the complete `inputs` object in `GITHUB_EVENT_PATH`. GitHub's documented workflow-dispatch payload representations need not preserve that brittle duplicate equality. A valid bounded JSON object therefore failed before every effect.

The cleanup's `test ! -e /dev/kvm` was also impossible on a GitHub runner that legitimately exposes the host device. Device presence says nothing about whether this workflow opened KVM. The same defect existed in intermediate steps. Cleanup must prove only transaction-owned non-use and residue, not absence of a host capability.

All four exact predecessor failures remain consumed, zero-artifact, completed-failure observations with no source effect:

1. run `32558263561`, workflow head `a201d5688013377069b6fb4a36159360dc307cae`, reviewed H `62bcfbcd58f90d0e329683e3297693c32bb71877`;
2. run `32560385792`, workflow head `7ccb35d14d749a0ef14602889ce2b52934c03d4d`, reviewed H `67b1ca45f101f98c56b2717549e9252a38a9f2a1`;
3. run `32561859288`, workflow head `549126bd7ba72d571d53113722e766967aaa0d23`, reviewed H `5f8c04899422ccf546c0f500b3647a5816b2675c`;
4. run `32563007701`, workflow head G8 `7f43d9acc5897b11b5d9794eb2e184767446aa48`, reviewed H8 `d05bbc5928bda9b6bd27da1c290b0238219fd185`.

## Decision

Use `cogs.stage2-static-control-dispatch-guard/v5` as the byte-identical first workflow step. Retain all trusted-environment and typed-input identity bindings. `GITHUB_EVENT_PATH` has one role only: open a no-follow regular file, enforce the 1 MiB bound, read it completely while its identity is stable, parse strict JSON, and require the root value to be an object. No payload field duplicates an authorization decision, and the production guard has no caller-supplied event alternative.

Use separate bounded diagnostics for event-path absence, event I/O, byte/type bound, file instability, JSON parsing and non-object roots: `EVENT_PATH_REJECTED`, `EVENT_IO_REJECTED`, `EVENT_BOUND_REJECTED`, `EVENT_STABILITY_REJECTED`, `EVENT_JSON_REJECTED` and `EVENT_OBJECT_REJECTED`. No diagnostic includes payload, path, exception or token bytes.

The authenticated complete single-page history is closed world. It must contain all four exact predecessors above, each at attempt 1 with exact repository, head repository, path, branch, event, workflow head, title-reviewed-H binding, completed status and failure conclusion. Every unknown, missing, duplicate or mutated run rejects. The v5 generation must contain exactly one current run, the trusted `GITHUB_RUN_ID` must identify it, and it must be the singular earliest ID for that generation. Token isolation, response bounds, redirect rejection and all existing fixed API diagnostics remain unchanged.

Replace every `/dev/kvm` absence assertion with a static-only runtime boundary. Before materialization, bind the exact reviewed bytes of the only three effect entrypoints and take a bounded root-owned `/proc` process/fd census. After removal of transaction-owned fixtures, revalidate the same source policy, boot/PID/network context and a second bounded census. Reject any workflow-owned KVM fd, QMP or owned-runtime Unix socket, qemu/containerd/ctr/shim/virtiofsd/network-tool process, or separate network namespace. Exact owned path cleanup remains required. The immutable-preparation HTTPS acquisition remains explicit and is not mislabeled as guest-network startup. A pre-existing host process or `/dev/kvm` device is outside workflow ownership and is neither rejected nor claimed absent. Source policy prevents short-lived forbidden launch routes; the pre/post census detects retained owned processes and descriptors without claiming an impossible complete history of unrelated host activity.

The implementation commit H9 is a direct child of G8 and contains v5, this ADR, the source-policy/census boundary and hostile/static tests while retaining the prior reviewed-H binding. Its direct child G9 changes the guard/workflow/static-test binding to exact H9 and regenerates deterministic readiness evidence. Neither commit dispatches a workflow.

## Authority boundary

This decision authorizes local implementation, portable hostile/static tests, exact H9 and direct-child G9 commits, and deterministic readiness regeneration. It authorizes no dispatch, rerun, artifact claim, KVM action, QMP/runtime/task/network lifecycle, AWS credential/API/provider/OpenTofu/SSM/inventory/campaign execution, deployment, release, retry or future replacement. Every terminal event outcome remains fail closed and grants no further attempt.
