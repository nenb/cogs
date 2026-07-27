# ADR 0067: Reallocate Phase B correction highs

- Status: Proposed
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Amendment scope: This ADR amends only four non-transferable ADR 0066 Phase B per-file gross-addition maxima: `completion_kata_operation.py` from 360 to 400, `completion_kata_process.py` from 430 to 600, `completion_kata_runtime.py` from 520 to 800, and `scripts/run-stage2-phase-a-candidate.py` from 220 to 240. Every other per-file high and the absolute Phase B high of 3,310 remain unchanged. Every non-conflicting ADR 0065–0066 requirement remains binding.

## Context

ADR 0066 was accepted with a 3,310-line absolute Phase B high. The corrected hostile integrated rereview of the implementation against exact baseline `84b30d30b3307f1c5222dd9e50dfa755cdee673a` rejected the implementation and kept the sole `phase-b-discovery` event gate closed. The rereview requires sound recovery corrections for exact findings P1-A through P1-G, authentic coverage for P2-A, and readable lifecycle code for P3-A. It is not a signoff and does not disposition any of those findings.

The current gross-addition distribution measured from that same baseline is:

| Counted file/surface | Current gross additions | ADR 0066 high | Position |
| --- | ---: | ---: | --- |
| `completion_kata_actions.py` | 14 | 40 | within high |
| `completion_kata_coordinator.py` | 478 | 500 | within high |
| `completion_kata_inputs.py` | 149 | 260 | within high |
| `completion_kata_network.py` | 199 | 280 | within high |
| `completion_kata_operation.py` | **363** | **360** | blocked |
| `completion_kata_process.py` | **516** | **430** | blocked |
| `completion_kata_qualification.py` | 251 | 320 | within high |
| `completion_kata_runtime.py` | **688** | **520** | blocked |
| `completion_kata_ssh.py` | 54 | 90 | within high |
| `scripts/run-stage2-phase-a-candidate.py` | **221** | **220** | blocked |
| Phase B schema | 220 | 220 | at high |
| `run-stage2-completion-remote.sh` | 0 | 20 | within high |
| **Absolute Phase B aggregate** | **3,153** | **3,310** | **157 remaining** |

The aggregate remains below its accepted high, and the other named files retain substantial unused space, but ADR 0066 makes each file high non-transferable. The four security-critical files are therefore blocked independently even before completing the required recovery corrections. Deleting code or compressing lifecycle transitions to fit the stale per-file highs would create invalid credit and would directly conflict with the rereview's readability finding.

This is a per-file allocation problem only. It is not evidence that the accepted aggregate, implementation scope, lifecycle semantics, event rules, timeout, retry policy, or authority boundary is insufficient.

## Decision

If accepted, replace only the four per-file maxima below. Leave every other ADR 0066 per-file maximum and the absolute Phase B aggregate unchanged.

| Counted file/surface | ADR 0066 high | Revised high |
| --- | ---: | ---: |
| `scripts/run-stage2-phase-a-candidate.py` | 220 | **240** |
| `completion_kata_qualification.py` | 320 | **320** |
| Phase B schema | 220 | **220** |
| `completion_kata_actions.py` | 40 | **40** |
| `completion_kata_operation.py` | 360 | **400** |
| `completion_kata_process.py` | 430 | **600** |
| `completion_kata_inputs.py` | 260 | **260** |
| `completion_kata_network.py` | 280 | **280** |
| `completion_kata_runtime.py` | 520 | **800** |
| `completion_kata_ssh.py` | 90 | **90** |
| `completion_kata_coordinator.py` | 500 | **500** |
| `run-stage2-completion-remote.sh` | 20 | **20** |
| **Absolute Phase B high** | **3,310** | **3,310** |

Against the current measurement, the revised individual headroom is 37 lines in operation, 84 in process, 112 in runtime, and 19 in the runner. These individual margins are not additive authority: only 157 aggregate Phase B lines remain across every counted surface. The 3,310 aggregate is always binding even though the sum of the independent file ceilings is larger. Unused room in any file does not authorize another file to cross its revised maximum, another surface, or another behavior.

Gross additions remain measured against exact baseline `84b30d30b3307f1c5222dd9e50dfa755cdee673a`. Deletions, replacements, renames, moved logic, generated code, excluded surfaces, tests, workflows, or presentation compression create no credit. The highs are maxima, not targets. Stop and replan before crossing any revised per-file maximum or the unchanged aggregate.

## Required finding closure

This numeric amendment does not waive, narrow, or itself resolve the corrected integrated rereview. Before the event gate can be considered, the implementation must resolve the exact findings in full:

- **P1-A — rootfs acquisition ownership:** perform one exact acquisition with durable ownership before an unrecoverable cut; remove the duplicate acquisition and prove cleanup/recovery at every acquisition cut.
- **P1-B — later-process recovery and signaling:** make recovery reachable from the mandatory later cleanup process without rerunning the sole discovery lifecycle; identify and revalidate exactly what may be signaled, handle parent-death reparenting soundly, and forbid group-wide action based only on a leader identity.
- **P1-C — truthful journal transitions:** never convert supervisor or cleanup uncertainty into absence; never synthesize lifecycle proofs; and authorize rootfs release only from actual, durable teardown evidence.
- **P1-D — closure-only grants:** make candidate grants obtainable only inside the fixed no-argument coordinator closure and remove caller-invocable factories or generic caller-selected command/spec execution surfaces.
- **P1-E — runtime/private-layout recovery:** recover the rename-before-publication cut, refuse adoption of intent-only or foreign state, use retained identities for narrow cleanup, and durably prove ownership of every private containerd, Kata, layout, and mount object before destructive action.
- **P1-F — complete independent residue proof:** treat normal empty Linux `/proc/<pid>/cmdline` values correctly and independently observe every owned residue class, including nft, tc, operation-directory entries, shares, mounts, and retained identities; never report `complete:true` from incomplete pathname-only observation.
- **P1-G — exception-safe descriptor closure:** acquire, track, and close every descriptor exception-safely; aggregate close failures; and do not advance ownership state while mandatory descriptor closure remains uncertain.
- **P2-A — authentic integrated tests:** exercise the actual hosted candidate owner graph and production parsers rather than source matching, encoded-row facsimiles, or synthetic substitutes. Coverage must include actual retained-root container information, authentic archive supervision, timeout-to-later-process recovery, rejection of broad signaling/deletion, every rootfs and layout crash cut, descriptor fault cuts, nft and complete residue observation, and the report-after-zero-residue boundary.
- **P3-A — readability:** present security transitions, proof construction, mutation, recovery, and cleanup in ordinary readable code. Semicolon chaining, multi-action lines, one-line proof synthesis, or other cap-driven compression is not an acceptable correction.

These summaries preserve rather than replace the exact rereview findings. A correction that satisfies only the summary wording while leaving any condition of P1-A through P1-G, P2-A, or P3-A unresolved fails this ADR's gate. P1-A through P1-G require sound recovery and ownership semantics already required by ADRs 0065–0066; this amendment grants no new production behavior.

## Tests, measurement, and exact review

Before any `phase-b-discovery` event, run and pass every focused, native-Linux, and offline test applicable to the complete corrected implementation. At minimum retain all ADR 0065–0066 checks, including:

```sh
npm run format:check
npm run typecheck
npm run schemas
npx tsx --test test/aws-stage2-completion-kata-*.test.ts
python3 -I test/aws-stage2-completion-kata-network.py
python3 -I test/aws-stage2-completion-kata-runtime.py
python3 -I test/aws-stage2-completion-kata-s5.py
git diff --check
npm run check
```

On native Linux amd64, also run the process, root-owned operation, guarded real-input, owner-graph, recovery-cut, descriptor-fault, and residue tests required by ADRs 0065–0066 and by P2-A. Offline or synthetic tests may supplement authentic coverage but cannot substitute for it. No hosted event is authorized as a test substitute.

Record a clean working tree, the exact full baseline and final 40-hex head, per-file gross additions, and the complete Phase B aggregate. Then obtain one independent hostile review of that exact baseline-to-head range. It must explicitly verify every P1-A through P1-G, P2-A, and P3-A disposition, readable presentation, all per-file and aggregate counts, applicable test results, and every retained ADR 0065–0066 boundary, with no unresolved P0–P3 finding. Any code, test, schema, workflow, or documentation change after review invalidates the signoff and requires remeasurement, applicable reruns, and a new exact review.

Until that clean exact review exists, the final event gate remains closed. Acceptance of this ADR would provide numeric room only; it would not by itself open or consume the event.

## Retained boundaries and consequences

This is a per-file-maxima-only amendment. It changes no production behavior, implementation scope, file list, owner model, lifecycle, event count or event-consumption rule, workflow trigger or permissions, stage marker, exact-head binding, 90-minute outer timeout, internal deadline, non-borrowing reserve, retry or recovery count, candidate metadata boundary, production permit, authoritative Phase B rule, workload authority, step-5 stop, release authority, issue-closure authority, cloud boundary, or AWS authority.

The same sole unconsumed `phase-b-discovery` event remains governed by ADRs 0065–0066. This ADR authorizes no label, ready transition, event creation, rerun, acquisition, KVM access, lifecycle execution, metadata upload, production use, workload, campaign, deployment, cloud action, or AWS action. Every non-conflicting stop remains binding.

The conservative global projection remains `33,344 < 34,000`. The 32,000 preferred target remains exceeded and documented; the 34,000 hard cap is unchanged. No aggregate or future-work allowance increases.

The consequence is only that the already-required sound recovery corrections may remain ordinary and reviewable in the files where that logic belongs, while the unchanged 3,310 aggregate continues to constrain the complete Phase B slice. This proposed documentation-only ADR creates no implementation or operational authority until accepted.
