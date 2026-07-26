# ADR 0056: Raise the native-invoker high for exact JSON types and readability

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing bounded-local delegation, after independent hostile review reported no P0–P3 findings.
- Acceptance record: [GitHub pull request #225](https://github.com/nenb/cogs/pull/225).
- Amendment scope: This ADR amends only ADR 0055's numeric gross-addition high for `test/aws-stage2-completion-rootfs-builder-native.py`, from 260 to 340, and its corresponding exact three-file total high, from 360 to 440. The workflow high remains 45 and the companion-test high remains 55. Every other ADR 0055 requirement and every retained requirement and stop from ADRs 0038–0054 remains binding.

## Context

The independent hostile implementation review retained at `/tmp/adr0055-implreview.md` reviewed the exact three-file implementation against baseline `1b13404d948368b5f421b4df0f5b837dd446ff03`. It reported one P1 and one P2, with no P0 or P3 findings.

The exact current gross raw additions are:

| Authorized file | Current gross additions | ADR 0055 high |
| --- | ---: | ---: |
| `.github/workflows/ci.yml` | +40 | 45 |
| `test/aws-stage2-completion-rootfs-builder-native.py` | +254 | 260 |
| `test/aws-stage2-completion-rootfs-builder.test.ts` | +50 | 55 |
| **Exact three-file total** | **+344** | **360** |

Deletions create no credit. The workflow and companion implementation were not implicated by either finding and require no change.

The P1 is exact JSON scalar typing. Python equality permits coercive matches that are invalid for this authority record: `2.0 == 2`, integer-valued floats can equal integer UID/GID values, and `1 == True`. The reviewed parser and validator therefore accepted malformed records with a floating-point version, a floating-point sudo identity, and a numeric substitution for the required boolean parent/child equality claim. ADR 0055 already requires exact record versions, exact complete sudo identity, exact equality claims, malformed-value rejection, and authentic negative variants through the same parser and validator. Ordinary Python equality does not satisfy that requirement.

The P2 is ordinary readability. The complete fixture's execution, source, and runner records and its fourteen-case mutation table were compressed onto physical lines approximately 207–744 characters long. The invoker has only six lines left under its current high. Keeping the 260-line high would reward line-cap compression and obstruct review of the exact field set and mutation coverage, contrary to ADR 0055's retained ordinary-readability requirement and its statement that highs are maxima rather than targets.

## Decision

If accepted, require only the already-scoped ADR 0055 invoker corrections below and raise only the numeric allowance needed to express them readably.

### Exact JSON scalar types

The authority parser and complete-record validator must reject Python-coercive equality. Every authority-bearing integer and boolean must have its exact JSON scalar type as well as its required value:

- record versions and sudo UID/GID values must be integers, with booleans and floating-point numbers rejected even when Python would compare them equal; and
- the sudo parent/child equality claim must be a boolean, with integers and floating-point values rejected even when Python would compare them equal.

The portable malformed-record table must exercise authentic complete-record variants through the same parser and validator used by the parent. At minimum, it must prove rejection of `2.0` for an integer version, floating-point substitutions for sudo UID and GID, and numeric substitutions for the boolean equality claim. These cases supplement the existing missing, extra, duplicate, malformed, context, workflow/source/runner, sudo, parent/child/PID1, and native-result cases; they do not replace or weaken them.

No alternate parser, test-only validation path, normalization, coercion, or selected-field substitute is authorized. String and null handling, exact shapes, duplicate-name rejection, complete-record equality, and every other accepted validation rule remain unchanged.

### Materially readable fixture and mutation table

Reformat the complete portable fixture and mutation cases into ordinary, materially readable Python. Nested records, field/value relationships, case names, mutation targets, and replacement values must be reviewable without deciphering compressed multi-hundred-character physical lines. Retain one complete valid fixture and compact table-driven mutation coverage, but do not flatten whole records or the complete case table onto a few cap-driven lines.

This is presentation authority plus the exact negative cases above, not authority to redesign fixture construction, validation, process observation, source identity, invocation, workflow behavior, or companion assertions. The final implementation must be materially readable as a whole, not merely below a mechanical line-length threshold.

### Revised exact file and gross-line bounds

Gross raw additions remain measured against exact implementation baseline `1b13404d948368b5f421b4df0f5b837dd446ff03`. Deletions create no credit, and unused allowance in one file cannot fund another.

| Authorized file | Authorized purpose | Maximum gross raw additions |
| --- | --- | ---: |
| `.github/workflows/ci.yml` | ADR 0055's unchanged exact fresh `native-c1` job | 45 |
| `test/aws-stage2-completion-rootfs-builder-native.py` | ADR 0055's invoker plus exact scalar-type rejection and readable fixture/mutation presentation | 340 |
| `test/aws-stage2-completion-rootfs-builder.test.ts` | ADR 0055's unchanged companion assertions and isolated invocations | 55 |
| **Exact three-file total** |  | **440** |

Thus the invoker high changes only from 260 to 340 and the exact three-file total high changes only from 360 to 440. The workflow high remains 45 and the companion high remains 55. These are maxima, not targets. The exact current `+40 +254 +50 = +344` measurement leaves 86 invoker lines and 96 total lines for the required exact-type negatives and ordinary formatting; it creates no reason to consume the margin.

Do not change the workflow or companion implementation to perform these corrections. Stop and replan before exceeding any per-file high or the 440-line exact three-file total, changing another implementation file, adding another implementation surface, or needing any behavior beyond the two reviewed corrections.

## Required final review

After correction and exact remeasurement, the complete final three-file implementation must receive a new independent hostile rereview. The final implementation must be materially readable and the rereview must independently verify the exact JSON scalar-type rejection, authentic negative cases, retained fixture/mutation coverage, exact per-file and total gross additions, and absence of regressions in every ADR 0055 requirement. Do not treat the prior review, a focused probe, formatter success, or passing portable tests as a substitute. Stop with no implementation authority while any P0–P3 finding remains unresolved.

## Retained scope and stops

This decision changes no native C1 logic other than exact rejection of the coercive malformed scalar variants already forbidden by ADR 0055, and no test behavior other than authentic negative coverage and readable presentation. It does not alter the fresh-job design, workflow steps or condition, source or runner identity, permission split, process observations, isolated launches, sudo provenance, complete-record shape, duplicate-name handling, pathname exclusions, companion assertions, timeout, or invocation policy.

ADR 0050's sole operationally selected non-authoritative candidate remains unconsumed. The `security` label remains absent. Every candidate, exact-source, run-attempt, duplicate-run, C1–C4, R1, Phase B, later-stage, step-5, campaign, production, issue-closure, timeout, retry, rerun, dependency, lockfile, schema, AWS, cloud, and mandatory-stop boundary retained by ADR 0055 remains unchanged. No fallback is authorized.

This proposed documentation-only decision performs no code, workflow, test execution, dependency, lockfile, network, Docker, KVM, candidate, campaign, production, cloud, or AWS action.

## Consequences

The raised invoker and total highs allow the exact scalar-type failures to be covered through the authentic validator while restoring ordinary reviewability to the complete fixture and mutation table. The workflow and companion highs and implementations remain unchanged, and the additional allowance grants no broader logic or scope.
