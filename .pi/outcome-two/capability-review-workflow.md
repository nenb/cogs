# Outcome 2 capability workflow hostile review

- **Reviewed head:** `9c86bc5add169fadd86574fd8468422a46ee3ed0`
- **Controlling decision:** accepted `docs/adr/0087-prepare-runtime-closure-before-capability-drop.md`
- **Other inputs:** `OUTCOME-TWO-PLAN.md`, `.pi/outcome-two/capability-implementation-gate.md`
- **Scope:** exact-head/credential/blob admission, event/attempt/concurrency, workflow-to-driver environment, ordinary-log disclosure, and the exact five capability surfaces.
- **Verdict:** **BLOCKED** — unresolved P1/P2 findings remain. No workflow observation is authorized by this review.

## P0

No findings.

## P1

### P1-1 — The ordinary log report discloses prohibited UID/GID map values

**Lines:**

- `scripts/runner-capability-probe.py:687` reads and returns the numeric rows from `/proc/self/uid_map` and `/proc/self/gid_map`.
- `scripts/runner-capability-probe.py:1312-1317` merges those rows into `namespaces.user_direct_root` in the emitted report.
- `schemas/runner-capability-probe-v1alpha1.json:190-200` requires `uid_map` and `gid_map` report fields.
- `schemas/runner-capability-probe-v1alpha1.json:429-430` admits the numeric ID-map arrays.
- `test/runner-capability-probe.test.ts:132-138` and `test/runner-capability-probe.test.ts:302-304` preserve and test this disclosure instead of rejecting it.

ADR 0087 line 217 explicitly prohibits UID/GID in the capability report. On a successful user-namespace case, the driver places the actual inside/outside/count triples into the canonical JSON line retained in the ordinary GitHub log. The earlier field inventory in `.pi/outcome-two/capability.md` is not controlling because ADR 0087 line 210 retains it only subject to the controlling disclosure changes.

**Required resolution:** report only closed categorical map behavior/status, with no UID/GID values, and add a hostile disclosure mutation that rejects numeric ID-map rows.

### P1-2 — Two non-transferable per-file hard highs have already been crossed

**Lines:**

- ADR 0087 lines 292 and 298-305 set non-transferable highs of 400 lines for `test/runner-capability-probe.test.ts` and 100 lines for `test/outcome-two-runner-capability-workflow.test.ts`.
- `test/runner-capability-probe.test.ts:401-411` are additions beyond its 400-line high.
- `test/outcome-two-runner-capability-workflow.test.ts:101-103` are additions beyond its 100-line high.

Measured from exact predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa`, the files have 411 and 103 gross added physical lines respectively. The aggregate is below 2,830, but ADR 0087 explicitly denies transfer between per-file highs. This is an immediate replan/stop condition, so the implementation gate cannot close at this head.

**Required resolution:** return each surface to its accepted high without moving logic to evade accounting, or accept a new ADR before proceeding.

## P2

### P2-1 — The credential gate does not prove that every extraheader and credential-bearing remote is absent

**Lines:**

- `.github/workflows/outcome-two-runner-capability.yml:46-50`
- `test/outcome-two-runner-capability-workflow.test.ts:38-46`

The regex at workflow line 49 matches URL-scoped forms such as `http.https://github.com/.extraheader`, but it does not match the valid unscoped key `http.extraheader`. Line 47 checks only fetch URLs; it does not inspect `git remote get-url --push --all origin`, so a credential-bearing `remote.origin.pushurl` also survives the gate. The static tests merely search for the words `credential` and `extraheader` and the fetch-only command, so both omissions pass.

This contradicts ADR 0087 line 177, which requires the shell to prove that no Git credential helper, credential-bearing remote, or HTTP extraheader remains before driver invocation. The later `/usr/bin/env -i` still prevents ambient Git configuration from entering the driver environment, but it does not make the claimed checkout credential-cleanliness proof true.

**Required resolution:** reject scoped and unscoped `http.*extraheader` forms, inspect fetch and push URLs/configuration, and add executable hostile tests for both bypasses without printing credential values.

### P2-2 — The gate's required exact-predecessor whitespace check fails on the current head

**Lines:**

- `.pi/outcome-two/capability-implementation-gate.md:3-4`

The gate requires `git diff --check <accepted-exact-predecessor>...HEAD`. Running the exact check against accepted predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa` fails because lines 3-4 of the gate document itself contain trailing whitespace. Therefore the gate's listed portable/static checks are not all green at the reviewed head.

**Required resolution:** make the exact required check pass, or explicitly replace that requirement through an accepted controlling decision.

## P3

No findings.

## Focus areas with no additional finding

- The workflow has exactly the accepted three steps and only the pinned checkout action.
- PR head, checkout SHA, base SHA, `github.sha`, `github.workflow_sha`, event merge SHA, and source-head workflow blob digest remain separately named.
- The driver/schema/workflow working bytes are compared with the exact checked-out head's Git blobs before driver execution.
- The trigger, same-repository condition, exact label, attempt-one condition, three-minute timeout, PR-scoped concurrency, and `cancel-in-progress: false` match ADR 0087.
- The driver is invoked through `/usr/bin/env -i`; only the reviewed public controls and three blob digests are passed. No ambient `PATH`, `HOME`, proxy, locale, complete `GITHUB_*`/`RUNNER_*` environment, token, or secret is passed.
- No artifact, cache, summary, comment, attestation, upload, or post-processing step is present. The observation remains `authority="none"` and `qualified=false`.

## Verification performed

- `npx --no-install tsx --test test/runner-capability-probe.test.ts test/outcome-two-runner-capability-workflow.test.ts` — passed, 6 tests.
- `npm run schemas` — passed.
- `npm run format:check` — passed.
- `npm run typecheck` — passed.
- `git diff --check bec0a19b0b984f88ab9c2effc5059f3737915caa...HEAD` — failed as described in P2-2.
- Gross additions from the accepted predecessor were measured with `git diff --numstat`: 411 and 103 for the two over-high test surfaces.
- A local Git configuration challenge confirmed that the workflow regex omits `http.extraheader` and the fetch-only URL check omits a credential-bearing push URL.

CAP-REVIEW-WORKFLOW COMPLETE.
