# ADR 0327: Retire failed formal generation and separate runtime contracts

- Status: Accepted
- Date: 2026-09-09
- Deciders: Nick Byrne
- Scope: failed Stage2 formal qualification recovery and one complete replacement non-AWS chain; no AWS

## Context

Protected main qualification revision Q `b11adc47c454bde0dc0e2930012e418b90917555`, sole parent G `eb59cae18e0f041a243f35f253d46713f7e87142`, described H `c10fc103532f3e3a8b746727bd0f48c6d8498148`. Exact mixed preflight `34301325559`, attempt 1, passed and two independent audits accepted it. Formal qualification `34302034014`, attempt 1, admitted the exact chain and started seven fresh hosted runners.

All seven owner entrypoints, cleanup-only recovery calls, fixed-root settlements, independent residue observations, staging cleanup, hosted-scaffold restoration, and final observations succeeded. Every cycle then failed closed before artifact upload because exact typed receipt publication returned exit 2. No cycle artifact or aggregate package exists. The run cannot establish formal qualification, promotion, production, provider, or AWS authority.

Independent source and historical audits found a deterministic producer/consumer incompatibility. Formal receipt production projects twelve static source fields plus `host_attestation_sha256`, while its consumer requires a fourteenth `runtime_attestation_sha256`. The existing runtime attestation is live, operation-specific evidence. Adding it to the common source object would conflict with the aggregator's requirement that immutable bindings agree across seven fresh cycles. Tests manufactured the missing consumer field rather than composing the real producer with the consumer. The configured result-schema commitment names the ordinary local report schema rather than the formal receipt contract. Silent error collapse and a missing publication-directory fsync made the failure harder to adjudicate, but final enforcement correctly remained red.

## Decision

Retire the complete failed generation from authorization use. Add exact typed selection vetoes for:

- revisions H `c10fc103532f3e3a8b746727bd0f48c6d8498148`, G `eb59cae18e0f041a243f35f253d46713f7e87142`, and Q `b11adc47c454bde0dc0e2930012e418b90917555`;
- runs `34282898803`, `34292774279`, `34293986674`, `34301325559`, and `34302034014`;
- artifacts `10079099187`, `10081986019`, and `10082440691`.

The closed policy, closed Python copy, and all 19 current pre-effect workflow mirrors must contain the same complete 24-revision, 29-run, and 20-artifact set. Preserve successful historical observations and exact bytes. Do not retry, relabel, reconstruct deleted partial receipts, delete historical artifacts for credit, or treat retirement as an ancestry veto. Shared canonical rootfs, OCI layers, runtime binaries, trees, and content digests are not globally retired; authenticated retired provenance prevents their reuse as successor authority.

Correct the contract as a versioned static/live split:

1. Formal source bindings contain only authenticated reusable inputs. Replace the absent live field with `runtime_manifest_sha256`, derived from exact held runtime-manifest bytes already committed by the envelope and static control. Keep ordinary historical local bindings and codecs unchanged.
2. Keep live runtime evidence per cycle in the existing exact QMP lineage, timing, network, journal, full-workload proof, and readiness lineage. It must remain fresh and distinct across cycles; no qualification-cycle live identity becomes a package-wide production commitment.
3. Emit formal receipt v2 and pre-AWS package v5. Bind the actual self-contained formal receipt schema, not the legacy ordinary report schema. Preserve historical schemas as non-authorizing history.
4. Authenticate every static source binding independently against reviewed control bytes rather than accepting seven agreeing substitutions.
5. Compose the actual formal producer with the exact validator for one full and six readiness fixtures through typed owner boundaries. Hand-built consumer-key fixtures alone are insufficient.
6. Emit only fixed bounded diagnostic categories, never receipt values, journals, keys, paths, environment values, or exception text. Fsync final files and their publication directory before success.
7. Migrate provider-free production package, approval, receipt, evidence, and workflow contracts to the same static/live split before declaring the non-AWS prerequisite handoff complete. This permits only static and synthetic-fixture validation; it does not permit an AWS CLI, provider, OpenTofu, SSM, inventory, deployment, or campaign operation.
8. Server-filter every successor first-created query by its exact head and require one complete returned history row. Pagination without authenticated `total_count` equality cannot prove uniqueness.
9. Bind readiness QMP lineage to the durable QEMU-role record at mint time. Restore `/run/netns` and `/opt` only from per-resource acquisition records written before each mutation.
10. Retain exact cycle receipts/status for the same 90-day window as their hash-only aggregate package; summary hashes never substitute for detailed evidence bytes.
11. Require exact scalar types for provider-free effect receipts, bound external JSON reads before allocation, use bounded CLI diagnostics, and hold report output-directory identity through publication and fsync.

Any malformed, partial, mixed-version, unbound, stale, retired, failed, retried, cancelled, cleanup-uncertain, persistence-uncertain, or residue-bearing input remains fail closed. Cleanup-only recovery retains no mint, retry, or launch authority.

## Bounded accounting

This correction was discovered only after the previous endpoint consumed every planned file and left insufficient gross-addition margin. Preserve all existing anchors, no-deletion-credit rules, owner separation, rename/copy/textconv prohibitions, and ordinary mode requirements. Raise only these ceilings for the measured contract correction and already-authorized replacement closure:

| Bound | ADR 0326 | ADR 0327 |
| --- | ---: | ---: |
| remediation global gross | 21,800 | 29,000 |
| integration owner gross | 4,550 | 11,000 |
| integration planned new files | 37 | 64 |
| total planned new files | 45 | 72 |
| tracked files | 1,465 | 1,492 |
| correction deployment | 22,300 | 24,500 |
| correction retained | 13,100 | 16,000 |
| correction workflows | 5,500 | 6,000 |
| correction global | 43,000 | 47,000 |
| post-H deployment | 150 | 1,500 |
| post-H retained | 2,000 | 4,000 |
| post-H workflows | 600 | 1,200 |
| post-H global | 2,500 | 6,000 |
| conservative hard retained lines | 98,000 | 100,500 |

The additional file allocation covers this ADR, versioned schemas/validators/fixtures, later H/G/Q decisions, and thirteen preserved v6 static-package members. Existing owner highs and source-byte/serialized-inventory limits remain unchanged unless a measured endpoint proves a narrower explicit change is necessary. Staying below a raised ceiling does not waive review or make an unlisted path free.

## Required gates

Before replacement H:

1. exact retirement policy/mirror equality and every new tombstone rejection pass;
2. real producer-to-consumer full/readiness composition, seven-cycle aggregation, static-binding substitution, identity replay, mixed-version, malformed canonical input, short-write, fsync, and diagnostics tests pass;
3. provider-free production package-to-approval-to-receipt-to-evidence fixtures pass while provider seams remain unreachable;
4. workflow syntax, exact source inventory, schemas, accounting, full local checks, and deterministic readiness regeneration pass;
5. two independent reviews report no P0-P2, followed by changed-since-review verification;
6. protected checks pass and the merged tree equals the reviewed tree.

Only then establish fresh H and run the complete fresh chain: sole first-created attempt-one producer; direct-child G; sole publisher; sole static observation; direct-child Q with exact read-back v6 bytes; exact mixed preflight with two accepting audits; then one sole first-created attempt-one seven-runner qualification and two accepting artifact/custody audits. A failure retires that complete generation and grants no rerun.

## Consequences

Run `34302034014` remains useful only as a historical observation that seven owner routes settled while publication rejected their receipts. It supplies no artifact, package, qualification, promotion, production, or AWS authority.

This decision authorizes the bounded correction and one complete replacement non-AWS authoritative chain under the owner's continuing instruction. It grants no AWS, provider, OpenTofu, SSM, inventory, deployment, campaign, production effect, release, Stage3, Stage4, or OpenBao-production operation. After the final non-AWS handoff, stop immediately before AWS.
