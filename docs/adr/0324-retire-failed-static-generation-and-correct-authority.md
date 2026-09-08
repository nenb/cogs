# ADR 0324: Retire failed static generation and correct authority

- Status: Accepted
- Date: 2026-09-08
- Deciders: Nick Byrne
- Scope: failed Stage2 static generation, replacement admission and boundary correction; no AWS

## Context

ADR 0320 established implementation H `97bc8eb8520a2116914c65a9ec5929e82c34ebf3` and direct-child control G `942e84cd8f977ee23a97dc47ce4a5d2d7510b346`. Producer `34183885618`, artifact `10040293103`, publisher `34192071842`, and publisher artifact `10042564354` passed and were independently audited.

The sole first-created static observation `34192787285`, attempt 1, failed closed before materialization or acquisition. H's `scripts/stage2-prebuilt-static-control-runtime-boundary.py` expected workflow SHA-256 `4c031ad4d0ef0dbd25e69f721902f019f37b248ca79f88b5fb48cbf63cfe9693`, but H's checked-out static workflow hashed to `df7c64c644a8e86835b30d1da4b328387716f0a3c0eaf7f098b3c9bcec115e60`. The expected value belonged to retired H `8907eba3191d07573cd84573cb0b2adddff17bd6`. Cleanup passed, no static artifact existed, and no AWS, provider, OpenTofu, SSM, KVM, deployment, inventory, or campaign operation occurred.

The published historical OCI subject is `ghcr.io/nenb/cogs/stage2-rootfs@sha256:fcf1f1d00cfd926b158cb81fe559181f778c1cca59c1d06cff1c500fa547d091`; descriptor SHA-256 is `4458ca8d0350328f4f91722cf87e52bd624f7303dd787c8e57a62aff9b9734db`. It remains immutable history and is not deleted. Its provenance binds the retired generation and cannot authorize a successor. The content-identical canonical rootfs layer is not globally retired.

Review also found that producer, mixed-preflight, and qualification first-created queries partitioned history with a server-side `branch=main` filter, while preflight and qualification additionally partitioned by caller-derived display titles. A failed same-workflow dispatch at the exact head through another ref or with different inputs could be omitted from a later generation-wide count.

## Decision

Permanently retire the exact failed generation:

- revisions H `97bc8eb8520a2116914c65a9ec5929e82c34ebf3` and G `942e84cd8f977ee23a97dc47ce4a5d2d7510b346`;
- runs `34183885618`, `34192071842`, and `34192787285`;
- Actions artifacts `10040293103` and `10042564354`.

Preserve every historical record and prior tombstone. Add these typed identities to both closed retirement-policy copies and every current pre-effect workflow mirror. Retirement remains an exact-selection veto, never an ancestry veto or authorization grant. Do not rerun the failed static observation or reuse its producer, publisher, descriptor, artifact, or OCI provenance.

Authorize one replacement implementation correction:

1. finalize the replacement static workflow, including retirement mirrors and generation-wide first-created admission;
2. hash those exact current workflow bytes and bind that value as the H source-policy member in the static runtime boundary;
3. make the portable boundary regression copy the current tree, prove exact acceptance, mutate one byte, and prove rejection;
4. require producer, publisher, static, mixed-preflight, and qualification first-created queries to paginate all workflow-dispatch runs and select only exact head plus exact workflow path, without server-side branch, display-title, or caller-input partitioning;
5. retain separate protected-main, actor, ref, attempt, ancestry, and supplied-predecessor authentication checks.

The replacement G must inherit the replacement H static workflow unchanged, so the boundary's H workflow commitment also matches the active G workflow bytes without a self-referential hash. Any later control-only change to that workflow requires a separately authenticated dual-role commitment or another replacement generation.

After local tests, deterministic evidence, accounting, independent review, and protected checks, the protected correction result may be frozen as replacement H. Run one new first-created producer, establish one sole-parent G through a closed decision/evidence commit, then run one new publisher and one new static observation. Every successor identity must be fresh.

ADR 0322 remains absent and reserved for exact replacement static-package Q, mixed preflight, and seven-runner qualification. Populate all Q seals together from the audited replacement chain; stale or placeholder H/G/workflow/control/descriptor/run/artifact values remain fail-closed.

Measured no-deletion-credit accounting after this correction leaves only 81 global and 111 integration lines, which cannot safely hold a closed G decision plus Q's thirteen members, complete seal updates, tests, and evidence. Raise only the remediation global gross high from 21,000 to 21,400 and integration owner high from 3,750 to 4,150. Reserve exact ADR 0325 for the fresh H control decision, raising the integration planned-new-file high from 34 to 36 and total planned-new-file high from 42 to 44 for ADRs 0324 and 0325. The expected remaining G/Q closure is below 250 gross integration lines; the new bounds leave additional correction margin without requiring deletion credit or compressed guards. Every byte, tracked-source, post-H, mutable-owner, correction-global, conservative hard, and other owner ceiling remains unchanged.

## Consequences

The failed generation is historical and non-authorizing. This decision grants no producer reuse, publisher reuse, static retry, Q, preflight, qualification, production, release, Stage3/Stage4 exit, AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign authority. Model-key revocation after hydration into a live worker remains unresolved.
