# Stage 3 S3-09 Linux/KVM exit evidence

## Accepted scope

- Issue: #71.
- Validation source revision: `9f6e241f4bc3a7ee32c1682d140e14c0e72489f5`.
- Profile: `linux-kvm`.
- Authority: `authoritative-local`.
- `release_eligible`: `false`.
- Accepted KVM artifact: `kvm-qualification-29875168103-1`.

This is an exit record for the local Stage 3 S3-09 criterion only. It is not a broader release or production acceptance.

## Automatic acceptance

| Workflow evidence | Run | Accepted outcome |
| --- | ---: | --- |
| CI | `29875168111` | Quality and Pi embedding, Secret scan, and Images, vulnerabilities, and SBOMs passed. |
| Insecure container smoke | `29875168130` | `insecure-container` passed as a functional-only companion. |
| KVM qualification | `29875168103` | `linux-kvm` passed as the authoritative-local profile. |

All five automatic checks passed on the validation source revision. The accepted KVM metadata records:

- `launcher.s3-09.integrated` passed with authorization, audit, revocation, identity, and network-enforcement dependency modes all real.
- The normal `launcher.smoke` passed in the same authoritative workflow.
- KVM acceleration was present and active; guest root and distinct guest boots were observed.
- The Stage 1 Envoy suite completed with applicability-aware stubbed results; those results are not relabelled pass or real. Separately, the Stage 3 real-runtime bearer report and sidecar and the integrated S3 report passed with all declared dependencies real.
- Launcher state and sensitive export cleanup completed, owned resources were absent after shutdown, and the externally provisioned roots were unmounted after the launcher sequence.
- The raw export remained local, was opened with pinned Pi as the current session, and was removed after validation.
- The external real-provider call using a provider API key was blocked and not run.

The insecure-container result is functional-only companion evidence. It does not supply isolation authority. The Linux/KVM result is the authority for this local exit record.

## Criterion mapping

| S3-09 criterion | Accepted evidence |
| --- | --- |
| Clean KVM and trusted services | The fixed launcher sequence used active KVM isolation and real trusted authorization, audit, revocation, identity, and network enforcement services. The Stage 1 Envoy companion retained its applicability-aware stubbed result labels; separate Stage 3 real-runtime bearer and integrated S3 evidence passed with declared dependencies real before the final gate. |
| Fixed HTTP Pi and Git scenario | The fixed HTTP Pi scenario completed read, edit, and bash tool operations and created a real Git commit. Local trusted composition resolved the model API key runtime-only for the pinned Pi deterministic stream, without an external call or persistence. No scenario content is reproduced here. |
| Allowed and denied egress | The allowed credential request was bound to the current fixture instance and succeeded; the companion policy-denied request was denied. Trusted observers were required to remain coherent without fabricating traffic claims. |
| Continuous events and durable history | The live event count was greater than 32 and at most 1000, the oldest cursor produced the required replay gap, and paged durable history remained available. |
| Git mapping | The untrusted client observation reported the expected Git mapping, which was validated through the fixed metadata boundary. |
| Metadata-only audit | OTLP evidence remained metadata-only, completion correlation passed, and leak checks passed. |
| Raw export opening | Pinned Pi opened the validated raw export as the current session before shutdown; the local sensitive export was then removed. |
| Shutdown and destruction | Shutdown reached zero owned resources, sensitive state was absent, launcher roots were unmounted, and the conformance guest was destroyed. |
| Applicability-aware prerequisite evidence | The Stage 1 Envoy suite completed with its stubbed results unchanged and was not treated as pass or real. The separate Stage 3 real-runtime bearer report and sidecar and integrated S3 report passed with declared dependencies real; normal launcher smoke and all prerequisite CI checks also passed. |

## Artifact and limit boundaries

All 9 downloaded KVM artifact files were tied to the exact source revision and passed their applicable schema and semantic validation. Across all 9 files, sensitive-content scans passed for these categories: credentials; prompts and command text; source content and tool output; raw or private paths; raw and native identifiers; and fixture markers. Only the two launcher reports additionally passed scans for URLs, proxy coordinates, and digest fields. This report records only those categories, not the scanned values.

Accepted implementation bounds:

- `dev/launcher/**/*.ts`: 13,333 lines / ADR 0036 hard limit 13,400.
- `src/**/*.ts`: 22,610 lines / hard limit 23,400.
- The result remains within the accepted ADR 0036 and ADR 0037 boundaries.

## Non-claims

- No AWS or other cloud resources were provisioned; GitHub Actions was used for automatic validation.
- No external real-provider call using a provider API key was made.
- No EKS, deployment, release, compliance, or production-readiness claim is made.
- This evidence exits local Stage 3 S3-09 only; it does not establish cloud or production authority.
