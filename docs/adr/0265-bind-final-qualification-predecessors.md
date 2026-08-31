# ADR 0265: Bind final qualification predecessors

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-31

Qualification run `33390184550`, attempt 1, control `2c2933858f72fa762edb6c5a24bc8edb53bcdf24`, was rejected by the pre-effect admission job. The exact workflow history still ended at run `33350122895`; it did not yet admit completed failed run `33366721195`. No implementation source was acquired, no lifecycle ran, no artifact exists, and the rejected observation grants no claim.

Extend the closed first-created history with both immutable failed predecessors:

- `33366721195`, attempt 1, H `1fc2dea2dcefea2aaf71a80356e0f5ed946e9991`, G `9f6cca5fcc059d3316cc702d2cc9f4b46b36079c`, failed after the full lifecycle and before publication; and
- `33390184550`, attempt 1, the same H, G `2c2933858f72fa762edb6c5a24bc8edb53bcdf24`, failed at pre-effect admission.

Require exactly 18 rows: those 17 immutable predecessors and one current attempt-one observation. Bind the corrected workflow SHA-256 `70234e13f666384bd10a9deb569da14a40f504d0a9cbd18c1f5ffd9c2e24adb9` in the qualification guard. H, the static-control package, V3 schema binding, lifecycle, publication, cleanup, and all security bounds remain unchanged.

Authorize review, CI, merge, exact protected-main control-variable update, and one fresh formal qualification. Raise the complete tracked-source cardinality bound from 1,226 to exactly 1,227 files. Failed observations remain non-authorizing. This grants no retry within an observation and no AWS, provider, deployment, campaign, production, release, or promotion operation.
