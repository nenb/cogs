# ADR 0347: Add a direct KVM driver diagnostic lane

## Status

Accepted under the owner's explicit instruction to continue the improved non-AWS process through Rows 4–10 and stop before the AWS campaign.

## Context

Protected-main `d033b9c427a8cc1f886d21bd2613036e039b71b2` passed exact Product execution for both empty and nonempty profiles in a fresh Linux/x86_64 VM, using the reviewed stock worker and sandbox image identities. Both generations settled with zero Docker residue and are diagnostic only.

Row 4 still requires repeated fresh KVM diagnostics of the exact `dev/linux-kvm/qualify.sh` plus `driver.sh prepare-cache` plus isolated `ci-smoke.sh` path before spending the single protected KVM candidate. The existing reusable prebuilt Stage 2 diagnostic exercises a different rootfs/full-cycle path. Osito is unavailable until an interactive Tailscale check is approved. Neither limitation justifies consuming protected qualification as a debugger or weakening the convergence gate.

No protected Product or KVM workflow has consumed `d033b9c4`. This new source change supersedes it before dispatch and invalidates its Product diagnostic for the eventual candidate; it does not retire authoritative evidence.

## Decision

Add a separate protected-main, manual, attempt-one-only direct KVM diagnostic workflow. Each dispatch:

- has `permissions: {}`, accepts no input, token, secret, artifact, provider, or caller-selected revision, and manually fetches exact public `GITHUB_SHA` with prompting and credential helpers disabled;
- root-creates a run-bound diagnostic generation before source effects, uses a fresh GitHub Ubuntu 24.04 runner, validates KVM/root/boot identity, authenticates the fixed guest image, and executes the exact current driver smoke path;
- creates one exact network namespace and boot-bound lease, verifies empty IPv4 and IPv6 filter tables, runs smoke only inside that namespace, and deletes the namespace before the lease on the healthy path;
- validates both reports locally, emits only a bounded `authority:"diagnostic-only"` status line, uploads nothing, and removes its local receipt on success.

Separate dispatch run IDs produce separate generations. Rerunning an existing run is rejected by `GITHUB_RUN_ATTEMPT == 1`; repeated convergence uses fresh dispatches. A failed, uncertain, or residue-bearing generation grants nothing and is not retried.

The lane cannot satisfy protected Product/KVM authority, H/G/Q, preflight, qualification, production approval, or AWS readiness. After this workflow merges, exact Product diagnostics must be repeated because the candidate source identity changed. At least three fresh direct-KVM dispatches must pass before exactly one fresh first-created attempt-one protected Product/KVM pair may be dispatched.

Transfer 400 unused governance lines to Product: governance changes from 5,800 to 5,400 and Product from 4,800 to 5,200. Add only the workflow, this ADR, and the two existing exact workflow-count tests to the applicable literal allowlists. The total 22,157-line tranche, all byte limits, global hard stop, source limits, local-tofu-ssm allocation, readiness allocation, and final-HGQ reserve are unchanged. There is no deletion credit.

No AWS, provider initialization, OpenTofu, SSM, inventory, deployment, campaign, H, G, or Q operation is authorized. Work stops immediately before the first AWS campaign operation.
