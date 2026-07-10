# CI and conformance schedule

This schedule implements `IMPLEMENTATION.md` sections 7.1 and 11.3 without treating development profiles as security evidence.

| Profile/check | Pull requests | Nightly | Security-labelled change | Release/AWS campaign |
|---|---:|---:|---:|---:|
| Format, lint, typecheck, unit, schemas, Pi spike | Every PR | — | Every PR | Re-run on release revision |
| Helm non-deploying scaffold | Every PR | — | Every PR | Replaced by deployment validation in its assigned stage |
| Container build, secret/license/dependency/vulnerability scan, SBOM | Every PR | — | Every PR | Re-run on release images |
| `insecure-container` conformance | Stage 1: every security-relevant PR; target every PR once stable | Optional | Required | Required but never authoritative |
| `linux-kvm` runner qualification | On `security` label and manual dispatch | Daily at 03:17 UTC | Required | Required |
| `linux-kvm` conformance | Stage 1 onward: optional ordinary PR | Nightly | Required | Required authoritative local evidence |
| EKS/Kata conformance | Never in default CI | Never | Never without approval | Explicit, time-boxed AWS campaigns only |
| Full load ramp | Never | Never | Never | Stage 5 approved campaign only |

The KVM workflow fails when `/dev/kvm` is absent, when QEMU cannot start with `-accel kvm`, or when QMP `query-kvm` does not return both `present: true` and `enabled: true`. It never falls back to TCG/software emulation. GitHub-hosted KVM availability is monitored rather than assumed.

Adding the `security` label triggers the KVM qualification workflow. Once Stage 1 exists, the same labelled path must run the authoritative guest-root conformance job. Routine CI artifacts need not be committed; release-candidate reports belong under `docs/security-evidence/`.

## Vulnerability-noise triage

Trivy and `npm audit` findings block by default. A finding that is demonstrably unrelated to the change, unreachable, or caused by incorrect upstream metadata may receive a temporary ignore only through a security-reviewed PR. The ignore must record the finding identifier, evidence and rationale, narrow scope, accountable owner, creation date, and an expiry no more than 14 days later. The owner must remove or renew it through security review before expiry; an expired ignore is a CI failure, not a permanent exception.

Paid GitHub larger runners, third-party KVM runners, and all AWS jobs require Nick Byrne's explicit approval before use.
