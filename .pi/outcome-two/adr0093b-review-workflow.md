# ADR 0093 final exact-head hostile review — workflow, schema, and causal dispatch

- **Exact reviewed implementation head:** `0d934c9e03aae17a5f219f302cf5c09058d45c59`
- **Branch at review start:** `review/o2-93b-workflow`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Scope:** corrected Outcome Two workflow eligibility/dependency/final wiring, native report schema, schema/workflow acceptance, exact-reviewed-head authority, and ineligible-context real-client dispatch
- **Method:** fresh hostile static and portable-only review. No native selector or primitive, sudo, workflow dispatch/rerun, network acquisition, provider, cloud, AWS, OpenTofu, deployment, production, or release action was run. No implementation file was edited.
- **Verdict:** **BLOCKED**

## P0–P3 verdict

| Severity | Count | Disposition |
| --- | ---: | --- |
| P0 | 0 | None found |
| P1 | 1 | **Unresolved; blocking** |
| P2 | 0 | None found separate from P1-1 |
| P3 | 0 | None found separate from P1-1 |

ADR 0093 requires no unresolved P0–P3 before native execution can be proposed. This exact implementation head does not qualify.

## Finding

### P1-1 — The “exact-head” eligibility decision is made by the event head itself, so an unreviewed head can self-authorize native dispatch

**Requirements:** ADR 0093 decisions 1, 9, and 10; retained ADR 0090 sections 2 and 9.

The correction changed `native-qualification-eligibility` to an always-run job, but that job first checks out the caller/event-selected `${{ github.event.pull_request.head.sha }}` and then executes `scripts/native-qualification/common.py --eligibility` from that checkout (`.github/workflows/ci.yml:167-188`). Nothing in this workflow, its eligibility environment, or `evaluate_eligibility()` compares the event head to `0d934c9e03aae17a5f219f302cf5c09058d45c59` or to any separately fixed reviewed-head authority. `evaluate_eligibility()` requires only a syntactically valid SHA, same-repository PR, and attempt one (`scripts/native-qualification/common.py:158-164`). The later source admission likewise authenticates bytes against `context.head_sha`, which is the same event-provided head; it does not repair the missing independent pin.

Consequently a different same-repository PR head can supply its own eligibility implementation, return success, and release A–E. A fork head is also checked out before the same-repository verdict; where that SHA is fetchable through the PR object, the ineligible source is itself the program deciding that it is ineligible. This is the self-consistent caller authority ADR 0093 explicitly removed. Checking out the exact **event** head is not authentication of the exact **reviewed** head.

The corrected acceptance reproduces the mistake rather than detecting it:

- `scripts/validate-schemas.ts:443-446` asserts only that checkout uses the event-head expression.
- Its positive eligibility case deliberately accepts the arbitrary value `"a".repeat(40)` (`:472-485`), not the reviewed head.
- Its fork/attempt/push cases execute the trusted local `common.py` from the review worktree and then simulate `needs` (`:475-496`). They never model the parsed checkout replacing that gate program with the ineligible head's bytes.
- `test/native-qualification-common.test.ts:403-471` has the same trusted-local-gate split; its separate real-client sentinel loop is not driven by an independently pinned head.

Thus the tests prove that the reviewed `evaluate_eligibility()` rejects a hostile environment. They do not prove that the actual workflow selects that reviewed evaluator before deciding whether native client jobs may run.

**Required correction:** bind eligibility to a reviewed Git head fixed outside event-head-controlled bytes and caller-rendered command text; do not execute event/fork-head code before that trusted eligibility verdict; require the exact fixed head in the positive case and reject a different well-formed same-repository head; and causally drive parsed ineligible/fork/head-mismatch cases through the six real client entry points with untouched effect sentinels. The final result must continue to reject every failed, skipped, or cancelled dependency.

## Schema and workflow observations without separate findings

- The report schema parses as Draft 2020-12 JSON and remains a closed six-job top-level union with fixed job IDs, ordered check inventories, pass/fail coupling, seven cleanup fields, and bounded job-specific metadata. Manual hostile/static inspection found no separate P0–P3 schema defect.
- Workflow YAML parses. Eligibility and the final job use `always()`; A–E need Quality plus eligibility; integration needs eligibility plus A–E; all seven native/final checkouts name the PR-head expression; upload precedes `always()` cleanup; and the final environment inventories job, upload, and cleanup outcomes.
- The reviewed common CLI accepted the well-formed same-repository attempt-one environment and rejected attempt two, fork, push, malformed SHA, and failed/cancelled/skipped/empty/unknown final outcomes. All six real client entry points reached an injected pre-native effect sentinel under their literal `--workflow-bound` selectors.
- These positives are fail-closed for the reviewed bytes but do not close P1-1's missing independent reviewed-head authority.

## Portable/static verification

- Seven isolated Outcome Two Python portable suites: **PASS**.
- All seven portable suites under optimized Python: **REJECTED optimized mode**.
- Python AST parse across 17 production/client/portable files: **PASS**.
- Static workflow/exact-head/client-selector probe: **PASS for the declared event-head shape**.
- Native schema JSON parse and Ruby workflow YAML parse: **PASS**.
- `git diff --check`: **PASS**.
- `git fsck --no-progress --no-dangling`: **PASS**.
- ADR 0093 additions remain within the scoped highs: workflow `318/400`, schema `340/700`, schema registration `264/300`, common `1778/1900`, focused common test `491/1500`.
- Focused TypeScript/AJV and `npm run schemas` were not run because this clean worktree has no `node_modules`/`tsx`. No dependency installation or network action was attempted.

## Boundary

No native evidence exists for this reviewed head, and this review grants none. Native Jobs A–E, thin integration, sudo, workflow dispatch/rerun, artifact reliance, provider/cloud/AWS/OpenTofu/deployment activity, production, release, issue closure, and Outcome Two completion remain unauthorized.

# SIGNOFF: BLOCKED

Exact implementation head `0d934c9e03aae17a5f219f302cf5c09058d45c59` retains one P1 workflow authority defect: event-head-controlled code decides exact-head eligibility, while the acceptance substitutes the already-reviewed local evaluator and therefore cannot prove ineligible causal non-dispatch. **NO SIGNOFF.**
