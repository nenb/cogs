# ADR 0364: Retire stale-Q bindings and require complete static handoff

## Status

Accepted

## Context

The authenticated-runner replacement chain reached protected revisions:

- implementation H `6d2eff8ffa8fe525b5566a0ddded7d79e868ba16`;
- sole-child control G `c075458cf2d853200df57584c1b16cf38bd6e38c`; and
- sole-child qualification Q `f75d3f09990de4635cc3890efe0f5f6e783312bd`.

The attempt-one producer run `35928408355`, publisher run `35938320143`, and static-control observation run `35938533499` passed. Independent custody checks accepted artifacts `10780807449`, `10783357865`, and `10784336353`. The static package authenticated H, G, and static-control SHA-256 `448989760dc077d27ea9b4bba5e9cbe50007f63b42cd93d5c52f6129c5fdf4e4`.

Q was created by restoring only a generated-evidence file mode. That preserved H's executable preflight constants instead of completing the handoff from the newly accepted static observation. In particular, the protected Q still selected retired H `2076c2bd781a663d2b27fa478792fc133fa9fd42`, retired G `1956ea8da439de2ae137e6ccbc5650ca149fe815`, and retired static-control digest `b2a4475e9277640dea97dc1d9fcc69eeb9af44175ae9f83faf05ed482e5fa01a`.

The sole attempt-one mixed preflight, run `35946454149`, therefore failed terminally in its pre-mutation host-closure step. No hosted-mode, immutable-preparation, KVM, provider, AWS, or production effect ran. Qualification was not dispatched. The cleanup step also failed because GitHub did not expose outputs from the failed combined collection-and-staging step; its expected digest was empty. The collection path had failed before staging, so that secondary failure did not identify residue, but the topology was not robust enough for a later staging failure.

The failure is not evidence for retry, continuation, stitching, or reinterpretation. A new authoritative H/G/Q chain is required.

## Decision

1. Retire the failed generation additively in `config/stage2-retired-revisions-v7.json`:
   - revisions `8e9328c66a1ab930583e22f07ba6f17f23bc7d2e`, `f82c9e77acbd8cf1f963a46d73a9e70afb6f41d6`, `6d2eff8ffa8fe525b5566a0ddded7d79e868ba16`, `c075458cf2d853200df57584c1b16cf38bd6e38c`, and `f75d3f09990de4635cc3890efe0f5f6e783312bd`;
   - runs `35928408355`, `35938320143`, `35938533499`, and `35946454149`; and
   - artifacts `10780807449`, `10783357865`, and `10784336353`.
2. Preserve V1 through V6 byte-for-byte. V7 names V6 and its exact SHA-256 as predecessor, retains every prior entry unchanged, and adds only ADR0364 entries.
3. Mirror every V7 identity in all twelve authoritative workflow deny lists. Direct selection of any retired revision, run, or artifact remains fail closed.
4. Make the mixed preflight workflow consume the static-control digest emitted by authenticated package validation. The workflow must not carry an independent static digest that can diverge from the downloaded package.
5. Make `host-check` emit exactly three authenticated lines: verification, host-closure SHA-256, and package static-control SHA-256.
6. Separate non-mutating host comparison from root staging. A successful comparison step publishes both digests before a distinct staging step. Cleanup runs only when that comparison succeeded, so a staging failure retains an available exact digest while a comparison failure cannot invoke cleanup with an empty identity.
7. Require the next Q to complete the static handoff explicitly. After the fresh G publisher and static observation pass and are independently accepted, Q must bind the fresh H, G, static-control run, artifact, artifact digest, control digest, source manifest, and reviewed workflow/source hashes. A mode-only Q is insufficient.
8. Keep H generic where values do not exist until post-G observation. H contains the dynamic package-to-workflow digest handoff and cleanup topology; Q later supplies observation-specific constants in the qualification guard and mixed-preflight script.
9. The next authoritative sequence remains strict:
   - merge one reviewed corrective H through protected PR checks;
   - run exactly one attempt-one producer while H is protected `main` and independently accept it;
   - merge exact sole-child G without changing reviewed source bytes;
   - run exactly one publisher and one static observation and independently accept both;
   - construct and merge exact sole-child Q with the complete accepted handoff;
   - run exactly one attempt-one mixed preflight; and
   - only after accepted preflight evidence, run one seven-runner qualification generation.
10. Stage 4 generated evidence remains deterministic, separate, blocked, and non-authorizing. No retired evidence grants AWS, IAM, approval, or production authority.

## Bounded replan

The historical five-task accounting remains gross and deletion-blind. This correction extends the reviewed matrix through ADR0366 and raises only planned task ceilings:

- governance: 8,550 lines / 1,300,000 bytes;
- product: 5,060 lines / 2,200,000 bytes;
- local-tofu-ssm: 6,200 lines / 3,300,000 bytes;
- readiness-ci: 278 lines / 10,000,000 bytes; and
- final-HGQ: 4,694 lines / 4,700,000 bytes.

The remaining line tranche becomes 24,782 and the global line forecast becomes 42,782. The remaining byte tranche stays exactly 21,500,000 and the global byte forecast stays exactly 29,500,000 by moving 500,000 bytes from final-HGQ to readiness-ci for repeated deterministic source-inventory regeneration. The final-HGQ pre-H cap remains 604 lines / 1,700,000 bytes; its post-H reserve becomes 4,090 lines / 3,000,000 bytes. The readiness allocation retains four deletion-blind generated-line transitions for the later G and Q regenerations. Four planned new files raise the tracked-file limit from 1,564 to 1,568. No source-inventory byte limit is raised.

## Consequences

- Run `35946454149` is terminal and cannot be rerun for authority.
- The valid bytes in artifacts `10780807449`, `10783357865`, and `10784336353` remain historical evidence only; they cannot seed or authorize the replacement chain.
- A static observation is not fully handed off merely because its artifact exists. Q must consume every accepted identity needed by preflight and qualification.
- Package validation is the single source of the staged static-control digest.
- Cleanup no longer depends on outputs from a failed step that also performed root mutation.
- Any failure in the replacement producer, publisher, static observation, mixed preflight, or seven-runner qualification is terminal for that generation.
- Production R, AWS planning, IAM readiness, approval, and campaign execution remain blocked until the fresh seven-runner qualification package is independently accepted.
