# Issue #364 — offline destructive-test and aggregation harnesses

**Scope:** local/static synthetic fixtures only

**Machine report:** [`stage5-destructive-harness-report.canonical-json`](../security-evidence/stage5-destructive-harness-report.canonical-json)

**Schemas:** [`stage5-destructive-fixture-suite-v1.json`](../../schemas/stage5-destructive-fixture-suite-v1.json) and [`stage5-destructive-report-v1.json`](../../schemas/stage5-destructive-report-v1.json)

## Boundary

`scripts/stage5-destructive-harness.ts` is a pure, bounded state-machine evaluator. It accepts canonical caller-supplied fixture bytes and caller-supplied governing-source bytes. It does not read files or environment variables, launch a process, open a network connection, contact a model, inspect a runtime, or invoke cloud, provider, cluster, deployment, scheduler, controller, or retry behavior. The test supplies local bytes explicitly.

The committed suite has exactly 22 cases: process, proxy, OpenBao, OTLP, WAL, disk, SSE, JSONL, Git, skill, and hostile-output faults, each represented once in the `functional-insecure` lane and once in the `authoritative-local-linux-kvm` applicability lane. The duplicated lanes classify where a future real test could apply; both executions here are synthetic. In particular, the report fixes `environment_observed=false`, `authority_claimed=false`, `authoritative_runtime_cases=0`, and all qualification/release fields to false.

The harness is not an executor or campaign driver. It has no facility for actual destructive operations.

## Deterministic lifecycle contract

Every fixture is a closed transition script:

1. the fixture parent acquires one or two named synthetic resources;
2. the parent admits one bounded operation;
3. the fault actor injects exactly the case's named fault;
4. the parent applies the exact categorical response;
5. the parent cleans every owned resource exactly once in reverse acquisition order; and
6. the parent closes the fixture.

Missing, duplicate, reordered, child/fault-owned, foreign, or post-close cleanup is rejected. Case duplication, reordering, profile substitution, fault substitution, sequence replay, extra actions, and unknown prompt replay are rejected. The report exposes only cleanup counts and categorical state; it never includes fixture payloads.

## Expected outcomes

| Fault | Required synthetic outcome |
|---|---|
| process | revoke admission, report the in-flight prompt outcome as unknown, never replay it |
| proxy | revoke admission, deny credentialed egress, drain the connection |
| OpenBao | treat loss/stale metadata identically: revoke admission, deny new credential use, drain |
| OTLP | bound the queue, drop with a counter, continue ordinary work |
| WAL | deny credential use and revoke admission when full/unwritable |
| disk | reject the uncommitted write, preserve prior bytes, report explicit failure |
| SSE | reject a replay gap and require paged history, never prompt replay |
| JSONL | reject a malformed tail, revoke admission, report an in-flight outcome as unknown, never replay |
| Git | emit a mapping-unavailable warning and preserve the settled turn |
| skill | reject an oversized artifact before it enters a prompt or guest copy |
| hostile output | truncate as inert data and aggregate metadata only |

OTLP, Git, disk, SSE, and hostile-output cases intentionally model the bounded-degradation rules in `DESIGN.md`; calling those expected continuations fail-open would be incorrect. Credential-use paths remain fail closed.

## Canonical and hostile-input rules

Fixture input must be strict UTF-8 canonical JSON with code-point-sorted keys and one trailing LF. SHA-256 bindings are domain separated for the suite, each case, and the source set. Input is bounded before hashing by byte, node, depth, key, string, property, and aggregate canonical-byte limits.

The snapshot layer accepts only plain/null-prototype JSON objects and dense ordinary arrays with enumerable data properties. It rejects accessors without invoking them, recursive proxies before traps, symbols, hostile prototypes, sparse/extended arrays, cycles, unsafe numbers, oversized keys/strings/graphs, noncanonical bytes, BOMs, and proxied byte arrays.

The source binder requires the exact ordered 17-path inventory. It hashes exact bytes into bounded metadata records and then domain-separates the canonical source-set root. Missing, duplicate, reordered, renamed, empty, proxied, accessor-backed, per-file oversized, or aggregate-oversized sources reject aggregation.

## Metadata-only report

The report contains only fixed categorical outcomes, counts, profile/applicability labels, byte lengths, digests, reason codes, and fixed non-authority fields. It has no report field for prompts, source content, request/query bodies, credentials, raw output, logs, JSONL entries, Git data, skill content, session exports, timestamps, identities, approvals, or runtime observations. Each case repeats the exact source-set digest so it cannot be detached from the report's governing-source binding.

The committed report is rebuilt and compared byte-for-byte by `test/stage5-destructive-harness.test.ts`.

## Checks

```sh
npx tsx --test test/stage5-destructive-harness.test.ts
npm run schemas
npm run typecheck
npm run check
```

## Non-claim

A passing report proves only that this deterministic local/static harness classified its synthetic fixtures consistently with its bound sources. It does not execute or validate the production worker, proxy, OpenBao, OTLP collector, WAL, storage, SSE client, Pi JSONL, Git, skills, Linux/KVM, Kubernetes, cloud, or a provider. It supplies no S4-11 result, campaign approval, independent review, release-candidate evidence, Stage 5 gate result, production/release/GA/compliance authority, or authorization for a later run.
