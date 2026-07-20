# Stage 3 development launcher report

Production validation source revision: `d6c0e4bd29de8c9169f414b7c07b6a1311926a8b`.

Successful push-triggered validation runs for PR #161:

| Area | Run | Result | Evidence boundary |
| --- | --- | --- | --- |
| CI quality, Pi embedding, secret scan, images/vulnerabilities/SBOMs | [`29769899099`](https://github.com/nenb/cogs/actions/runs/29769899099) | pass | Quality/Pi, secret scan, image scan, and SBOM jobs completed successfully. |
| Linux KVM launcher evidence | [`29769898871`](https://github.com/nenb/cogs/actions/runs/29769898871) | pass | `launcher-linux-kvm.json` reported `launcher.smoke` pass with `authoritative-local` authority. |
| Insecure container launcher evidence | [`29769898452`](https://github.com/nenb/cogs/actions/runs/29769898452) | pass | `launcher-insecure-container.json` reported `launcher.smoke` pass with `functional-only` authority. |

Validation observations:

- CI `29769899099` passed the quality/Pi embedding job, secret scan, and images/vulnerabilities/SBOM jobs for source revision `d6c0e4bd29de8c9169f414b7c07b6a1311926a8b`.
- KVM qualification `29769898871` passed. The launcher evidence report is metadata-only, `release_eligible: false`, and records `linux-kvm` as `authoritative-local` only.
- Insecure container smoke `29769898452` passed. The launcher evidence report is metadata-only, `release_eligible: false`, and records `insecure-container` as `functional-only` with no isolation/default-deny or release evidence claim.
- Both launcher smoke reports used the fixed diagnostic `metadata-only launcher smoke passed; exact sensitive export and state cleanup verified`.
- The workflows externally provisioned `/run/cogs/egress` and `/run/cogs/ssh` as current-user tmpfs roots, required them empty before launcher use, and cleaned/unmounted them after the smoke run.
- The sensitive `launcher-smoke.json` export remained local to the runner, was validated and removed by the harness, and was not uploaded in either launcher evidence artifact.
- Downloaded metadata artifacts contained no uploaded `launcher-smoke.json`.
- Debug runs and diagnostic branches are not acceptance evidence for this report.

Applicability semantics:

- `insecure-container` remains `functional-only`; network isolation/default-deny evidence is not applicable, and it provides no release, production-readiness, compliance, deployment, or production-authentication claim.
- `linux-kvm` is the only `authoritative-local` development profile. Its KVM prerequisites and external tmpfs roots are validated/provisioned by the workflow, but this still does not imply release eligibility, cloud readiness, compliance status, deployment readiness, or production readiness.
- `macos-vm` has no fallback path in this stage.

No cloud statement: issue #70 launcher evidence performs no AWS, cloud provisioning, deployment, release, compliance, production-readiness, or production authentication operation.
