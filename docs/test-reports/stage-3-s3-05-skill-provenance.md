# Stage 3 S3-05 skill provenance and project context evidence

## Evidence scope

- Issue: #67, S3-05 skill provenance and project context loading.
- Evidence branch: `docs/stage3-s3-05-s3-07-evidence`.
- Applicability: local functional/provenance evidence.
- `release_eligible`: `false`.
- `isolation_authoritative`: `false`.
- AWS/cloud resources used: `false`.
- Credentials/content included in this report: `false`.

This report is retrospective. It maps accepted issue #67 criteria to merged implementation PRs and CI evidence. It does not update ADRs and makes no AWS, cloud distribution, release, deploy, or production artifact-distribution claim.

## Merged evidence PRs

| PR   | Purpose                                                 | Exact head                                 | Merge commit                               |
| ---- | ------------------------------------------------------- | ------------------------------------------ | ------------------------------------------ |
| #107 | Accepted issue #67 skill provenance ADR                 | `240e0d923c21a328b243295b11f2c406c642cb31` | `4c49735b5e925764a15a925a3e9cf4eef143d086` |
| #108 | Canonical skill bundle core                             | `133e3dd3a21f0a135f54f0b1736ba28d7a929692` | `17f8eba087609a383eebf7169f862d475c20f622` |
| #109 | Private skill snapshot store                            | `72fcbf0c17af8c3b715d8a0c7dff667b9e7ddc37` | `85ccbdfe16b3d910834b2a639868ea5af82a4488` |
| #110 | Local shared OCI skill resolver                         | `1a23d9272c87f19a67e9de02b1ccbf928e3d643f` | `fcd3754f38d9644877f7c9f84df49d3d1d93eec6` |
| #111 | Accepted issue #67 cap amendment                        | `9f42ca4d911af969376ba82df249a6ccc71eff1c` | `329c5f2f372f28cbb2e2f07e0b3a128236409ed2` |
| #112 | Verified skill preparation integration into Pi sessions | `633837ceee6d5078ba4bda6eaad521f4d05ce4a2` | `8a89daa004f7f5594796468ad8fca3f04d2ba824` |

Measured implementation checkpoints cited during review:

- Canonical bundle: 321 tests, 26.91 KB diff, production LOC 12,150.
- Private store: 332 tests, 45.28 KB diff, production LOC 12,787.
- OCI resolver: 337 tests, 33.83 KB diff, production LOC 13,287.
- Final integration: 351 tests, 103.94 KB diff, production LOC 14,495 / 15,100.

Cancelled duplicate CI entries observed during iterative review were administrative superseded runs. The accepted evidence is the successful exact-head checks on the PR heads listed above.

## Acceptance criteria mapping

| #67 criterion                                                                                                                | Evidence                                                                                                                                                                                                                                                                                                                                                                |
| ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Shared skills are immutable OCI artifacts pinned by digest; trusted materializer verifies before use.                        | #108 established canonical bundle bytes/digests/manifests. #110 added local OCI layout resolution pinned to exact digest descriptors. #112 integrated trusted materialization before Pi session use.                                                                                                                                                                    |
| Registry/object-store credentials never enter the guest.                                                                     | #110/#112 keep registry/object-store resolution and copy handles in the worker boundary; the guest receives verified read-only materialized bytes, not registry credentials.                                                                                                                                                                                            |
| Prompt text loads only from trusted verified copies, never from guest/SFTP content.                                          | #112 prepares trusted eager prompt text from verified shared/private skill artifacts before session start. Guest/SFTP content is not a trusted prompt source.                                                                                                                                                                                                           |
| The exact verified archive is copied into the guest read-only where supported and verified by digest before first use.       | #108 canonical archives and #110 OCI descriptors provide exact digest verification; #112 SFTP materialization enforces readonly modes where supported and checks digest-derived materialization paths before use.                                                                                                                                                       |
| Private user skills are snapshotted into content-addressed archives at session start; cross-user fetch/resolve fails closed. | #109 added user-isolated content-addressed private snapshots. Tests cover namespace separation, digest mismatch, hostile shapes, and cross-user denial/fail-closed resolve behavior.                                                                                                                                                                                    |
| Project context such as `AGENTS.md` is retrieved over SFTP, treated as untrusted, and bounded by file size/count.            | #112 added bounded untrusted AGENTS handling with explicit status reporting. Oversize, malformed, duplicate, and count-bound cases are rejected or reported without turning context into trusted configuration.                                                                                                                                                         |
| Skill/project content is untrusted instruction text and cannot alter trusted worker config, policy, auth, or telemetry.      | #108-#112 keep manifests/digests/config in worker-owned structures. Skill text and AGENTS content are inputs to prompt/context only and cannot mutate policy, auth, telemetry, or worker config.                                                                                                                                                                        |
| Load failures are recorded without failing the whole session unless required trusted provenance is missing.                  | #112 reports bounded AGENTS statuses and preserves session startup for optional context failures. Missing/invalid required trusted skill provenance fails closed before Pi side effects.                                                                                                                                                                                |
| Tests cover digest mismatch, missing artifact, cross-user denial, guest mutation, oversized context, and export metadata.    | #108 covers canonical digest/malformed bundle cases. #109 covers digest mismatch and cross-user private store denial. #110 covers missing/wrong OCI descriptors. #112 covers guest mutation defense, oversized AGENTS/context, cleanup, strict in-memory `skillMetadata` / export-ready handoff, and Pi integration; it does not persist authenticated export metadata. |
| Local artifact stores are cleaned/reset after tests.                                                                         | #109-#112 use temporary local stores/session roots and assert cleanup/dispose behavior; no persistent local collector or artifact service is required by this evidence.                                                                                                                                                                                                 |
| No AWS resources or cloud campaigns are used.                                                                                | All cited evidence is local functional/provenance testing and GitHub CI. No AWS/cloud resources or campaigns were created.                                                                                                                                                                                                                                              |
| Non-release boundary: local provenance/integrity evidence only, not release artifact distribution.                           | This report and the cited PRs are evidence-only for local provenance. Insecure-container and KVM checks are regression/security CI, not authority for artifact distribution or release eligibility.                                                                                                                                                                     |

## Security and behavior summary

The completed S3-05 slices establish strict digest and manifest verification for shared OCI skills, content-addressed private user snapshots, and trusted prompt construction from verified worker-owned copies only. User isolation is enforced by private store namespace and digest checks. Registry/object-store credentials are not exposed to the guest. SFTP materialization defends against guest mutation, stale paths, symlinks, forged handles, cleanup races, and unsupported file types. Untrusted `AGENTS.md` content is bounded by size/count and reports status rather than altering trusted worker configuration.

Load failure semantics are intentionally split: optional untrusted project context can be recorded/reported without failing the whole session, while required trusted provenance failures fail closed before session side effects.

## Evidence commands and reproducibility

Representative commands used across the cited slices and reproducible from the corresponding exact PR heads:

```bash
npm run typecheck
npm run test
npm run check
git diff --check
```

Secret scanning was performed in review with Docker Gitleaks on the working tree for the relevant exact heads. No local collectors, AWS resources, cloud services, or release/distribution infrastructure are required to reproduce this evidence.

## Limits and non-claims

- `release_eligible`: `false`.
- `isolation_authoritative`: `false`.
- No credentials, prompts, source content, command output, or private skill content are included in this report.
- Insecure-container and KVM checks are regression evidence only and are not authority for artifact distribution.
- No AWS, cloud, release, deploy, launcher, registry publication, or compliance certification claim is made.
