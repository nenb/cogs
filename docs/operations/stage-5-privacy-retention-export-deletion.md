# Stage 5 local/static privacy, retention, export, and deletion contract

Issue #365 is a **local/static synthetic contract only**. It performs no cloud, provider, object-store, cluster, deployment, Kubernetes, filesystem-deletion, or external-model operation. The checked report fixes EKS and object-store deletion to `unexecuted`, every execution/qualification/eligibility field to `false`, and cannot satisfy the provisional Stage 5 matrix's future privacy/deletion evidence category.

The contract consists of:

- [`schemas/stage5-privacy-deletion-suite-v1.json`](../../schemas/stage5-privacy-deletion-suite-v1.json), the metadata-only fixture shape;
- [`schemas/stage5-privacy-deletion-report-v1.json`](../../schemas/stage5-privacy-deletion-report-v1.json), the categorical/digest-only result;
- [`scripts/stage5-privacy-deletion.ts`](../../scripts/stage5-privacy-deletion.ts), the pure scanner and deletion reducer;
- [`test/fixtures/stage5-privacy/valid-suite-v1.json`](../../test/fixtures/stage5-privacy/valid-suite-v1.json), which contains no raw or sensitive fixture payload; and
- [`stage5-privacy-deletion.local-static.json`](../security-evidence/stage5-privacy-deletion.local-static.json), the canonical deterministic local report.

## Privacy surfaces and prohibited content

The fixture inventory has exactly six ordered surfaces: OTLP, logs, reports, events, crash summaries, and the export descriptor. The first five admit only bounded categorical, boolean, integer, and SHA-256 metadata. Their content and attachment-presence fields must be false. Crash dumps are not admitted; only a bounded crash-summary category and digest are represented.

The scanner rejects or categorizes:

1. prompt or model content;
2. source, complete command, or tool content;
3. credentials, private keys, authorization material, or placeholders;
4. private/raw identifiers;
5. arbitrary paths;
6. network query strings or bodies;
7. raw transcript/export content; and
8. attachment content.

Tests create canary values only in memory, one category at a time. The committed fixture and report contain no canary values, prompts, source snippets, commands, credentials, private IDs, paths, attachments, session JSONL, or raw export. A rejection returns only fixed categories, affected-surface enums, counts, and a domain-separated finding-summary digest. It never returns a field name or offending value.

This is a strict scanner rather than a general anonymizer. Unknown fields fail the suite schema even when they do not match a prohibited category. It does not claim that arbitrary natural language is anonymous or that future unconstrained formats can be made safe by pattern matching.

## Raw-export boundary

Raw export remains the explicit exception described by `DESIGN.md` section 14 and ADR 0022. This contract never embeds or reads a raw bundle. It accepts only an export descriptor whose boundary says all of the following:

- explicit user action is required;
- the authenticated non-tool API is the only surface;
- the model cannot call it;
- mode is `raw` and no sanitization/anonymization is claimed;
- `sensitive=true`;
- `attachments_included=false`; and
- raw payload/content presence is false in the scanned central fixture.

Changing attachment exclusion, sensitive marking, API/user-action/model-callability, or payload-presence state fails closed with a specific categorical reason. Actual raw export bytes remain in the existing user-owned sensitive local bundle boundary and are never valid central privacy fixtures or committed Stage 5 evidence.

## Retention contract

| Data class | Default | Explicit deletion |
|---|---:|---|
| Trusted Pi session state | 30 days (`2592000` seconds) after close | an authenticated user deletion request may start the same deletion sequence before expiry |
| Graceful-shutdown object copy | 30 days (`2592000` seconds) | same sequence; current object, every version, and every delete marker must be covered |
| Project workspace | retained until explicit workspace deletion | separate explicit workspace lifecycle; session expiry alone does not delete it |
| Attachments owned by deleted session data | never exported by default | absence must be asserted before terminal deletion success |

Expiry is a trigger, not proof of deletion. A retention deadline never converts an unknown object into absent and never permits skipped version enumeration.

## Canonical deletion state machine

For no legal hold, the only complete synthetic sequence is:

```text
retained
  -> request-accepted
  -> active-state-absence-asserted
  -> current-object-absence-asserted
  -> version-inventory-complete-asserted
  -> all-versions-absence-asserted
  -> all-delete-markers-absence-asserted
  -> attachments-absence-asserted
  -> final-absence-asserted
  -> deleted-verified (synthetic model only)
```

The version inventory carries only bounded counts and a digest. Object keys, version IDs, paths, provider responses, and deletion targets are prohibited report content. `deleted-verified` means only that the supplied synthetic transition list is exact and ordered. It does **not** mean any local file, EKS resource, persistent volume, or object-store object was deleted or observed.

Duplicate, missing, reordered, or unknown transitions produce `uncertain-stop`. An `operation-failed` transition produces `failed-stop`. An `observation-uncertain` transition produces `uncertain-stop`. Both states are terminal for this reducer: later asserted success cannot promote them, there is no retry/force/skip route, and unconfirmed targets remain preserved for a separately authorized resolution path. Failures and uncertainty use fixed reason codes; raw exceptions, provider payloads, logs, targets, and arbitrary diagnostics are forbidden.

## Legal hold is separate

A legal hold is an independently disclosed administrator decision, not a retention duration, deletion error, or uncertainty alias. The suite fixes:

- authority to `separate-administrator-only`;
- retention policy independence to true;
- failure and uncertainty are not holds; and
- an active hold admits no deletion transitions and returns `held-separate`.

The local reducer cannot set, clear, override, or authenticate a hold. A future implementation needs separate authorization, custody, disclosure, and audit evidence. Hold release would start a new authorized deletion sequence; it cannot resume after an unverified transition prefix.

## Bounds and hostile shapes

Before hashing or semantic validation, the scanner snapshots only plain JSON descriptors under fixed byte, node, depth, key, string, property, and array limits. Recursive Proxies are rejected with `util.types.isProxy` before reflection, so Proxy traps are not run. Accessors, cycles, symbols, sparse arrays, non-plain prototypes, typed arrays, unsafe numbers, and oversized input return categorical uncertainty; getter bodies are never invoked.

The output is deterministic canonical JSON. Input and finding digests are domain-separated semantic bindings, not identity, provenance, deletion, privacy, or evidence authentication.

## Remaining real work

Actual EKS/CSI/object-store retention, deletion, version enumeration, delete-marker removal, legal-hold enforcement, attachment deletion, failure recovery, and independent absence/zero-inventory observation remain explicitly unexecuted. They require a separately approved exact release-candidate campaign, real dependencies, authenticated and separated principals, a future evidence schema/validator, and independent review. No result from issue #365 authorizes that work or establishes release, production, GA, compliance, or Stage 5 exit.
