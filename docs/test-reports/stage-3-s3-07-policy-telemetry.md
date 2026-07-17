# Stage 3 S3-07 static policy and metadata-only telemetry evidence

## Evidence scope

- Issue: #69, S3-07 static policy and metadata-only telemetry.
- Evidence branch: `docs/stage3-s3-05-s3-07-evidence`.
- Current main after final command-audit merge: `7142dfea8a8b858258fb1d74246b9c6ba4b30644`.
- Applicability: local functional evidence plus GitHub CI.
- `release_eligible`: `false`.
- `isolation_authoritative`: `false`.
- AWS/cloud resources used: `false`.
- Credentials/content included in this report: `false`.

This report is retrospective. It maps issue #69 acceptance criteria to merged implementation PRs and records operational limitations. It does not update ADRs, does not add production code, and makes no production backend, compliance, cloud, release, or deploy claim.

## Administrative status

Issue #69 was prematurely closed during implementation and then reopened for the remaining accepted scope. That administrative correction did not change the acceptance criteria: acceptance remained open until the policy, telemetry, instrumentation, and disabled command-audit slices were reviewed and merged.

## Merged evidence PRs

| PR   | Purpose                                        | Exact head                                 | Merge commit                               |
| ---- | ---------------------------------------------- | ------------------------------------------ | ------------------------------------------ |
| #124 | ADR 0026 issue #69 scope and line budget       | `24929f751e6f1a53b72ed08fd9f15e7b43f4edc6` | `9be2c18f14255f93b3d59946af3902d28372469a` |
| #125 | Static policy core                             | `27da6f91acbe937cb6eef98c54101c097fb25d0a` | `7a3753215cc18f0218d6fa7dbad30dbe427fc964` |
| #126 | Static policy integration gates                | `b97d75ffa7eedb03a74337d6bba1b132e7cff5a9` | `3cb1faad2455e2b9eb3e1a3d18473744a929a189` |
| #127 | Shared OTLP core and worker telemetry sink     | `607e23100e01094e209814122211cae51e913364` | `063b4f3164196c27c4e29bd2eee9501142c6977c` |
| #128 | Metadata-only worker telemetry instrumentation | `05e247c7a40057f361e30943f21e4151f1fb753f` | `0a32da9d02b63db0c59818b388bf05e6797d2109` |
| #129 | Disabled command-audit hook contract           | `914b1a19a361f4d688bf63966ad32415e53548f0` | `7142dfea8a8b858258fb1d74246b9c6ba4b30644` |

Each PR above reached the same required five-check CI shape successfully on its exact head: Secret scan, Quality and Pi embedding, Images/vulnerabilities/SBOMs, insecure-container, and linux-kvm. No run IDs are asserted here; the evidence is the PR/check status for the exact heads listed.

Exact diff secret-scan sizes cited during review:

- PR #127: 82.42 KB diff Gitleaks pass.
- PR #128: 109.10 KB diff Gitleaks pass.
- PR #129: 11.39 KB diff Gitleaks pass.

Final production LOC after PR #129: 21,295 / 22,000. Final state-safe full check: 464 tests passed.

## Acceptance criteria mapping

| #69 criterion                                                                                                                                                                                                 | Evidence                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| One static authorization function covers mount/config validation, tool enable/dispatch, egress rule and secret use, export mode, and reserved restore action.                                                 | #125 added the static in-process policy core. #126 integrated policy gates across launch/config/mount, route-plan metadata, Pi model/tool/export decisions, egress authorization and secret-use metadata, and reserved restore denial.                                                                                                  |
| Policy never parses bash text and fails closed for unknown actions/fields/surfaces.                                                                                                                           | #125/#126 validate strict policy envelopes and metadata only. Bash dispatch policy sees tool metadata, not bash text. Unknown, malformed, extra-field, unsupported, hostile, and restore inputs fail closed with generic policy errors.                                                                                                 |
| Contract tests define an equivalent decision envelope suitable for future OPA adapter comparison.                                                                                                             | #125 added strict action/decision schemas and OPA-parity fixtures without adding an OPA runtime or dependency.                                                                                                                                                                                                                          |
| Emit spans/metrics for worker lifecycle, Pi events, tool dispatch, SSH/SFTP operation, egress authorization/completion, WAL depth, OTLP lag, export, and shutdown.                                            | #127 added bounded worker telemetry and shared OTLP transport. #128 instrumented lifecycle, Pi run/turn/event/history/model-call, tool enable/dispatch, SSH/SFTP connect/channel/operation/loss, egress authorize/complete, WAL append/depth/failure, OTLP queue/export health, checkpoint/export, and shutdown prepare/ready surfaces. |
| Automated assertions prove telemetry contains no prompt/model text, source content, complete commands, arbitrary paths, tool output, HTTP query/body, secrets, placeholders, account IDs, or raw identifiers. | #127/#128 added redaction, hostile input, exact vocabulary, safe integer, descriptor snapshot, throwing sink, and sentinel-negative tests across worker telemetry, Pi/tool/model usage, SSH/SFTP, ext-authz, completion, lifecycle, WAL, OTLP health, export, and shutdown.                                                             |
| OTLP outage does not stop ordinary work; audit authorization/WAL failure still denies credential use.                                                                                                         | #127 keeps worker telemetry drop/cooldown/outage nonfatal and separates it from egress telemetry reliability. #126/#128 preserve ext_authz ordering and WAL fail-closed behavior before credentialed egress allow. Tests cover worker outage, abort accounting, failed posts, cooldown, WAL failure, and completion correlation.        |
| Enterprise command-audit hook is disabled by default and separately protected if present.                                                                                                                     | #129 added a disabled-only frozen exact hook contract. The factory defaults disabled, external hooks are strictly descriptor-validated, enabled forgeries are rejected, supplied callbacks are not retained/invoked, and a real bash dispatch canary proves zero audit invocation and no fifth Pi tool.                                 |
| Redacted telemetry fixtures and negative leak tests are committed.                                                                                                                                            | #127/#128 committed OTLP envelope tests, worker telemetry hostile/forbidden-field tests, redacted real-surface tests, sentinel sweeps, and exact metric/span value assertions.                                                                                                                                                          |
| Local collectors are reset/destroyed after tests.                                                                                                                                                             | #127/#128 use local in-memory/ephemeral HTTP/OTLP test fixtures and close/abort paths; no persistent local collector is required.                                                                                                                                                                                                       |
| No AWS resources or cloud campaigns are used.                                                                                                                                                                 | All evidence is local functional testing plus GitHub CI. No AWS/cloud resources or campaigns were created.                                                                                                                                                                                                                              |
| Non-release boundary: local observability/policy evidence only, not production monitoring or compliance certification.                                                                                        | This report is evidence-only. It claims no production telemetry backend, command-audit compliance regime, cloud deployment, release readiness, or monitoring certification.                                                                                                                                                             |

## Static policy and integration details

The static policy core covers eight fixed actions: `mount.validate`, `config.validate`, `tool.enable`, `tool.dispatch`, `egress.authorize`, `secret.use`, `export.create`, and reserved-deny `restore.request`. It validates strict envelopes, uses deterministic decision IDs for allowed metadata, uses fixed non-content deny identifiers, rejects hostile descriptors, and keeps bash text opaque. Integration preserves ext_authz route matching and WAL ordering: route match and policy allow are required before WAL append, and WAL append remains required before credentialed egress allow.

## Shared OTLP and worker telemetry details

The shared OTLP HTTP/validation transport from #127 is reused by worker telemetry and existing egress OTLP telemetry. Staff-review fixes included endpoint/path validation, strict JSON response handling, content-length/request caps, redirect rejection, operation timeout, parent abort, response cancellation, oversize cancellation, partial-success validation, in-flight abort accounting, integer bounds, sums/gauges correctness, and no late writes/counter mutation after close.

The shared transport does not merge queue policies. Worker telemetry intentionally keeps bounded nonfatal drop/count/cooldown behavior, while egress telemetry retains the separate #66 reliability/retry semantics for authorization evidence. Worker telemetry outages can drop metadata during cooldown; ordinary lifecycle/Pi/tool/SSH/egress/WAL/export/shutdown results are not changed by worker telemetry sink failure.

## Instrumentation details

#128 added metadata-only instrumentation for real lifecycle, Pi, tool, SSH/SFTP, egress, WAL, OTLP-health, export, checkpoint, and shutdown surfaces. Tests assert exact metric values and event/outcome vocabularies, no false success spans, descriptor-only model/usage/tool metadata snapshots, no prompt/source/path/command/tool-output/HTTP query/body/secret/account/model/provider/raw ID leakage, and nonfatal throwing sinks.

API request span and W3C `traceparent` propagation were explicitly deferred because they were not needed for issue acceptance and would expand the security surface under the line budget.

## Command-audit boundary

#129 intentionally implements only a disabled-by-default no-payload hook contract. It does not design enabled audit payloads, retention, access control, compliance reporting, telemetry, or backend forwarding. A payload-bearing/enabled audit mode requires future review.

## Operational limitations

- Egress WAL bounds remain sticky fail-closed: max 1 MiB / 10,000 records. When WAL readiness is lost or append fails, credentialed egress is denied and in-session recovery is not attempted; recycle is required.
- `wal.depth` and `wal.failures` telemetry publish bounded metadata about depth/failure state, but do not recover the WAL or implement threshold warning behavior.
- OTLP worker telemetry loss remains nonfatal. Metadata may be dropped during queue pressure, outage, abort, or cooldown.
- This evidence does not assert a production telemetry backend, compliance command audit, or release posture.

## Evidence commands and reproducibility

Representative commands used across the cited slices and reproducible from the corresponding exact PR heads:

```bash
npm run typecheck
npm run test
npm run check
git diff --check
```

Docker Gitleaks scans were run during review on the exact diffs/working trees noted above. Tests use local/ephemeral telemetry fixtures and do not require AWS resources, cloud services, long-lived collectors, or production credentials.

## Limits and non-claims

- `release_eligible`: `false`.
- `isolation_authoritative`: `false`.
- No credentials, prompts, source content, command text, command output, HTTP bodies, account IDs, or telemetry payload contents are included in this report.
- CI and KVM are regression evidence only; this is not a release, deploy, cloud, monitoring-backend, or compliance-certification claim.
