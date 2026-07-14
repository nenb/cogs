# Architecture decision records

ADRs 0001–0010 were accepted by Nick Byrne on 2026-07-10. ADR 0011 is the Stage 1 proxy-selection gate and remains proposed until explicit review.

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
| [0011](0011-select-envoy-for-http-egress.md) | Select Envoy for initial HTTP egress | Proposed; Stage 1 gate |

Implementation pauses for every boundary listed in `IMPLEMENTATION.md` section 47. Superseding an accepted ADR requires a new ADR rather than editing history.
