# ADR 0264: Bind publication to the current V3 schema

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-31

Formal qualification run `33366721195`, attempt 1, completed exact admission, immutable preparation, the seven-sample Kata/KVM lifecycle, 21 measurements, report derivation, recovery, fixed cleanup, independent zero residue, output cleanup, and hosted scaffolding restoration. It failed closed before report freeze or upload. No artifact exists and the run grants no qualification claim.

The bounded full-publication diagnostic `33378704011`, attempt 1, consumed 8,512 canonical report bytes with SHA-256 `85a50462f91cc7c030066ed2f8a7b06255eda65972dae2cfbddb57f4cee13bd5`. The exact publication function rejected them with `LocalPublicationError: local report reviewed schema differs`. The report codec's current registry selects `schemas/stage2-workload-local-qualification-v3.json`, SHA-256 `57ff30b4adb601a7775dbefc9002c983152974ba3244aa449656c7e8a5f7dc27`, while the qualification guard still supplied historical V2 schema SHA-256 `27d60133f202d9c32381d2b3dc8fe281334dc67d59dc8d72b402e6b7ca825375`.

Correct the qualification guard and diagnostic rehearsal to supply the exact V3 schema digest. Preserve V2 and its historical digest unchanged. Add a direct current-schema digest assertion. This is a control correction for the already frozen implementation H and does not alter H, static-control bytes, lifecycle semantics, cleanup, or evidence meaning.

Authorize review, CI, merge, the exact protected-main control-variable update, and one fresh formal qualification after the correction is merged. Raise the complete tracked-source cardinality bound from 1,225 to exactly 1,226 files. Failed and diagnostic runs remain non-authorizing. This grants no retry within an observation and no AWS, provider, deployment, campaign, production, release, or promotion operation.
