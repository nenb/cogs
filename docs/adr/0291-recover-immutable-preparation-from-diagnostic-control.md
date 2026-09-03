# ADR 0291: Recover immutable preparation from diagnostic control

## Status

Accepted.

## Context

Protected-main reusable diagnostic run `33778071333`, attempt 1, again passed both actual no-mint routes. The full route passed after 57 minutes and readiness passed after 80 minutes. ADR 0290's operation-infrastructure correction also worked: cleanup passed the previously rejected journal-absent operation classification.

The next immutable fallback read the formal static-control member from the control root. A diagnostic lifecycle intentionally stages `stage2-current-source-prebuilt-diagnostic-control-v1.json` instead, so the formal member was absent. Both recovery jobs stopped before immutable rollback; settlement and residue did not run. The run remains non-authorizing.

## Decision

Add an explicit recovery-only diagnostic-control reader. It validates the canonical diagnostic control and every committed runtime/executable member through the existing diagnostic codec. It then authenticates the complete six-member external publication-custody directory against the canonical custody values and signature-verification digest committed by that control, and requires the external descriptor to equal the runtime's embedded descriptor.

Formal preparation keeps its existing rule that any external descriptor competes with reviewed formal control and is rejected. Fresh preparation does not gain a diagnostic fallback. Only the post-route immutable recovery path selects the diagnostic reader, and only when the exact diagnostic control member exists.

After immutable rollback succeeds, the unchanged settlement step remains responsible for removing fixed roots after process and mount scans, followed by independent residue proof. No mutable lifecycle path, work construction, receipt, retry, publication, qualification, or AWS route is added.

## Consequences

Run `33778071333` remains historical non-authorizing evidence despite both route passes. After exact-head review and protected CI, one new attempt-one reusable diagnostic may run. Producer, publisher, rehearsal, qualification, and AWS remain frozen until the complete aggregate passes and receives independent audit.
