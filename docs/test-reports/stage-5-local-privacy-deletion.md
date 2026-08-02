# Stage 5 local/static privacy and deletion validation

## Scope

- Issue: #365.
- Authority: `local-static-synthetic-privacy-classifier`.
- Inputs: bounded categorical/digest metadata and runtime-only generated canaries.
- Cloud/provider/Kubernetes/object-store/deployment/model execution: none.
- Actual EKS deletion: unexecuted.
- Actual object-store deletion/version removal: unexecuted.
- Qualified / campaign authorized / release eligible: false.

This report records a pure scanner and deterministic deletion-model contract. It is not the provisional Stage 5 matrix's future evidence-reference contract, is not bound to a frozen release candidate or authenticated principal, and cannot satisfy Stage 5 criteria 45.8 or 45.9.

## Covered surfaces

The strict fixture covers exactly OTLP, bounded logs, bounded reports, bounded events, bounded crash summaries, and the raw-export descriptor boundary. Safe surface fixtures contain only enums, booleans, bounded integers, and SHA-256 digests. No prompt, model output, source, complete command, tool output, credential/placeholder, private ID, arbitrary path, network query/body, attachment, transcript, crash dump, or raw export is committed.

Runtime-only generated canaries prove all eight prohibited categories are detected without reproducing a canary in the report. Separate negative tests cover prohibited field categories and path-, authorization-, and query-shaped scalar heuristics. Findings expose only ordered category/surface enums, count, and domain-separated summary digest.

## Export, attachment, and marking results

The valid descriptor is accepted only with explicit user action, authenticated non-tool API, `model_callable=false`, raw mode, no sanitization/anonymization claim, `sensitive=true`, `attachments_included=false`, and no raw payload in the scanned fixture. Isolated mutations of each boundary fail closed. Attachment inclusion and missing sensitive marking have distinct fixed reason codes.

This checks descriptor semantics only. Existing local raw exports remain sensitive user-owned bundles and are deliberately outside the scanner fixture and checked report.

## Retention and deletion-model results

The contract fixes trusted session state and graceful-shutdown object copies to 30 days (`2592000` seconds), preserves workspaces until explicit workspace deletion, and allows authenticated user deletion to begin the same sequence before retention expiry. The version policy requires current-object absence, complete version inventory, every version absent, and every delete marker absent before attachment and final absence assertions.

The exact eight-transition synthetic sequence deterministically reaches `deleted-verified`. Reverse, missing, duplicate, or out-of-order transitions stop uncertain. Injected failure and uncertainty states are sticky: later assertions cannot promote success, no retry is modeled, and unknown is never converted to absent. An active separately authorized/disclosed legal hold permits no deletion transitions and returns `held-separate`; deletion failure and uncertainty remain explicitly not legal holds.

## Hostile input and bounds

Tests reject root and nested Proxies without executing traps, reject accessors without invoking getters, and reject cycles, typed arrays, non-JSON values, oversized strings, arrays, object graphs, and canaries. The scanner bounds input/canonical bytes, nodes, depth, strings, keys, object properties, array length, canary count, and canary bytes before report generation.

The schemas reject unknown fields and couple all authority/execution fields to false. The canonical checked report is byte-for-byte regenerated in the test and keeps actual EKS/object-store deletion fixed to `unexecuted`.

## Artifacts

- Input schema: [`schemas/stage5-privacy-deletion-suite-v1.json`](../../schemas/stage5-privacy-deletion-suite-v1.json)
- Report schema: [`schemas/stage5-privacy-deletion-report-v1.json`](../../schemas/stage5-privacy-deletion-report-v1.json)
- Scanner/reducer: [`scripts/stage5-privacy-deletion.ts`](../../scripts/stage5-privacy-deletion.ts)
- Safe fixture: [`test/fixtures/stage5-privacy/valid-suite-v1.json`](../../test/fixtures/stage5-privacy/valid-suite-v1.json)
- Canonical local report: [`docs/security-evidence/stage5-privacy-deletion.local-static.json`](../security-evidence/stage5-privacy-deletion.local-static.json)
- Tests: [`test/stage5-privacy-deletion.test.ts`](../../test/stage5-privacy-deletion.test.ts)

## Remaining qualification

A separately approved campaign must test actual EKS session/workspace storage, object copies and backend version/delete-marker behavior, attachment ownership, legal holds, failures, uncertainty recovery, and independently observed absence against one frozen release candidate with real dependencies and authenticated separated principals. Issue #365 neither executes nor authorizes that work and makes no production, release, compliance, or Stage 5 exit claim.
