# Architecture decision records

ADRs 0001–0010 were accepted by Nick Byrne on 2026-07-10. ADR 0011 was accepted at the Stage 1 proxy-selection gate on 2026-07-14. ADR 0012 was accepted by Nick Byrne for the Stage 2 AWS runtime decision on 2026-07-14. ADR 0013 was accepted by Nick Byrne for the issue #64 SSH bash line-budget exception on 2026-07-15. ADR 0014 was accepted by Nick Byrne for the issue #65 model-auth scope and line-budget gate on 2026-07-15. ADR 0015 was accepted by Nick Byrne for the issue #66 Stage 3 egress integration scope and line-budget gate on 2026-07-15. ADR 0016 was accepted by the delegated project lead under Nick Byrne’s explicit delegation of project decisions to amend only the issue #66 line-budget cap on 2026-07-15. ADR 0017 was accepted by the delegated project lead under Nick Byrne’s explicit delegation of project decisions to amend only the issue #66 line-budget cap on 2026-07-16. ADR 0018 was accepted by Nick Byrne to amend only the issue #66 line-budget cap after the measured OpenBao metadata revocation attempt on 2026-07-16.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-embed-pi-with-closed-resource-loading.md) | Embed Pi with closed resource loading | Accepted |
| [0002](0002-use-ssh-sftp-sandbox-protocol.md) | SSH/SFTP sandbox protocol | Accepted |
| [0003](0003-external-proxy-and-default-deny.md) | External proxy and default deny | Accepted; concrete proxy proposed by ADR 0011 |
| [0004](0004-kata-reference-and-full-vm-profile.md) | Kata reference and full-VM profile | Accepted; AWS runtime pending Stage 2 |
| [0005](0005-preserve-native-pi-jsonl.md) | Native Pi JSONL | Accepted |
| [0006](0006-record-untrusted-git-observations.md) | Record untrusted Git observations | Accepted |
| [0007](0007-api-keys-first-external-oauth-broker.md) | API keys first; external OAuth broker | Accepted |
| [0008](0008-metadata-only-central-telemetry.md) | Metadata-only telemetry | Accepted |
| [0009](0009-content-addressed-skill-artifacts.md) | Content-addressed skill artifacts | Accepted |
| [0010](0010-qualify-github-hosted-kvm-per-run.md) | Per-run GitHub-hosted KVM qualification | Accepted |
| [0011](0011-select-envoy-for-http-egress.md) | Select Envoy for initial HTTP egress | Accepted |
| [0012](0012-use-aws-virtual-nested-kvm-for-stage-4-candidate.md) | Use AWS virtual nested KVM as Stage 4 candidate | Accepted |
| [0013](0013-bash-exec-scope-and-line-budget.md) | Allow a bounded Issue #64 line-budget exception for SSH bash | Accepted |
| [0014](0014-model-auth-api-keys-and-disabled-oauth-broker.md) | Issue #65 model-auth scope and line budget | Accepted |
| [0015](0015-stage-3-egress-integration-scope.md) | Issue #66 Stage 3 egress integration scope and line budget | Accepted; line-budget cap amended by ADR 0016, ADR 0017, and ADR 0018 |
| [0016](0016-raise-issue-66-line-budget-after-measured-slices.md) | Raise issue #66 line budget after measured secure-egress slices | Accepted; numeric cap superseded by ADR 0017 |
| [0017](0017-raise-issue-66-runtime-manager-line-budget.md) | Raise issue #66 runtime-manager line budget after measured remaining-work plan | Accepted; numeric cap superseded by ADR 0018 |
| [0018](0018-raise-issue-66-final-evidence-line-budget.md) | Raise issue #66 final evidence line budget after measured OpenBao revocation attempt | Accepted |

Implementation pauses for every boundary listed in `IMPLEMENTATION.md` section 47. Superseding an accepted ADR requires a new ADR rather than editing history.
