# ADR 0054: Authorize native-invoker companion assertions

- Status: Accepted
- Date: 2026-07-26
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-26 under Nick Byrne's standing bounded-local delegation, after independent hostile review reported no P0–P3 findings.
- Acceptance record: [GitHub pull request #223](https://github.com/nenb/cogs/pull/223).
- Amendment scope: This ADR amends only ADR 0053's exact authorized-correction scope to permit the bounded companion assertions below in `test/aws-stage2-completion-rootfs-builder.test.ts`. Every other ADR 0050–0053 requirement remains binding.

## Context

Accepted ADR 0053 authorized the minimum correction in the excluded test-only native invoker, but confined assertion updates to that invoker. Implementation commit `65fb2fa0c038257f8395e2d5ea1731256f3938d4` (`65fb2fa`) also updated `test/aws-stage2-completion-rootfs-builder.test.ts`, which already invokes the native invoker's portable path and inspects its source.

The independent hostile implementation review retained at `/tmp/adr0053-implreview.md` reported one P1 and no P0, P2, or P3 findings. The sole blocker was authority: the TypeScript companion-test change was necessary to replace its obsolete `synthetic_merge_sha` assertion and add reasonable regression checks for the corrected record, but ADR 0053 explicitly authorized only invoker-file changes.

That review found no behavioral weakening. It confirmed that commit `65fb2fa` independently validates and emits `envelope_sha` and `event_merge_sha`, matches each only to its own trusted context, rejects source collapse or substitution, retains exact-source checks, and changes no workflow, production surface, schema, dependency, lockfile, or counted code. This proposal supplies only the missing companion-test authority; it does not reopen the reviewed implementation design.

## Decision

If accepted, authorize only the necessary companion update in `test/aws-stage2-completion-rootfs-builder.test.ts` for ADR 0053's corrected native-invoker record.

The companion test must replace its obsolete exact `synthetic_merge_sha` source assertion and must require exact source-text assertions for both separately named record fields:

- `"envelope_sha": expected["envelope_sha"]`; and
- `"event_merge_sha": expected["event_merge_sha"]`.

It must also assert that the invoker uses its synthetic-context validator, compares `envelope_sha` exactly with `github_sha`, compares `event_merge_sha` exactly with `event_payload_merge_sha`, and contains no direct `envelope_sha == event_merge_sha` requirement. The existing portable and local invocations, their fail-closed status checks, and every unrelated assertion in the TypeScript test must remain unchanged.

These source-text checks supplement rather than replace the invoker's authentic accepted/rejected portable matrix. Neither synthetic value becomes source. The companion update may not remove, relax, bypass, or substitute any assertion for exact pull-request head, exact checkout, head/base distinction, repository, workflow/job, event/action, run ID/attempt, workflow SHA/blob, source blob, sudo provenance, parent/child, native observation, or fail-closed behavior. Missing, malformed, collapsed, cross-substituted, or locally fabricated values remain rejected.

### Exact line and file bound

Only `test/aws-stage2-completion-rootfs-builder.test.ts` receives this additional authority, with a maximum of **10 gross raw added physical lines**. At reviewed commit `65fb2fa`, the delta against parent `c1eb57f23b3eab424d6c07bf446237fc20378298` is six gross additions and deletion of the one obsolete assertion. Deletions create no credit. Stop and replan before exceeding the ten-line high or changing another companion file.

This excluded test change creates no counted-set or line-cap credit. ADR 0053 remains the sole authority for the native-invoker correction itself. No production, workflow, schema, candidate, counted-code, dependency, lockfile, source-baseline, timeout, invocation, or test-policy change is authorized.

## Candidate and retained stops

This decision adds, selects, consumes, replaces, or reruns no candidate. ADR 0050's sole operationally selected non-authoritative candidate remains unconsumed, and the `security` label must remain absent throughout implementation, ordinary CI, native qualification, remeasurement, and review.

Every retained C1–C4 and R1 gate, exact-source and exact-head check, formatter and portable/native/hostile review gate, counted high, candidate freeze and one-label-event rule, run-attempt rule, timeout, retry, rerun, duplicate-run, Phase B, later-stage, step-5, campaign, production, issue-closure, cloud, AWS, and mandatory-stop boundary from ADRs 0038–0053 remains unchanged. There is no fallback from a failed or ambiguous native record, no authority to weaken source, and no authority to treat either synthetic observation as source or candidate evidence.

This documentation-only proposal performs no code, workflow, schema, test execution, dependency, lockfile, network, Docker, KVM, provider, cloud, AWS, candidate, campaign, or production action.

## Consequences

The repository-level test can track the exact corrected native-invoker record and each observation's own trusted context without preserving an obsolete field assertion. The amendment closes only the scope defect identified in `/tmp/adr0053-implreview.md`; it does not weaken source identity, broaden implementation, change counted code, or advance any candidate or later-stage gate.
