# ADR 0357: Retire failed qualification and scope host-local observations

- Status: Accepted
- Date: 2026-09-22
- Decider: Nick Byrne
- Scope: terminal timeout-corrected H/G/Q generation, host-scoped runtime freshness correction, and one fresh non-AWS H/G/Q chain

## Context

ADR 0356 established qualification revision Q
`17380562a9fb9f7d08bea0269a9fdc5812b1faf7` over implementation H
`d98571b9f2be446ed478464d23df532d91b94e53` and direct-child control G
`431f7d2b63b4e5d4da7aca40e0f02ff0fca07f33`. The producer,
publisher, static observation, Q validation, and mixed preflight passed. Formal
qualification run `35685410662`, attempt 1, then ran all seven independent KVM
cycles successfully but failed closed in its aggregate job before publishing a
pre-AWS qualification package.

Authenticated readback preserved the seven exact cycle archives:

- `10678755703`, `10677962970`, `10678201915`, `10678118928`,
  `10677629335`, `10678169602`, and `10677874983`;
- each archive contains only its ordinal receipt and status;
- all seven host boot IDs, operation tokens, rootfs tokens, runtime identities,
  pre-SSH process facts, client keys, and host keys are distinct; and
- no planning, IAM setup, approval, provider execution, campaign, AWS effect,
  or aggregate evidence publication occurred.

The exact failure was `FormalQualificationError: reused live runtime
observation`. Cycles 1, 5, and 6 had equal `live_mapping_sha256`
`2ed7df8d83eb1ea77d87bea376eb362f756b6eeb59c2178a97b64b65c321979e`
while their host boots and all other freshness commitments were distinct. The
mapping digest commits host-local PID, device, inode, and mapping observations.
Fresh Linux hosts may legitimately allocate the same numeric values, so raw
digest equality across distinct host boots is not runtime reuse. QEMU runtime
identity and pre/post-SSH process-fact digests have the same host-local
namespace property. Synthetic fixtures had varied these values by ordinal and
therefore did not exercise realistic cross-host equality.

The independent terminal audit is
`sha256:6ff782d53a8fa8781bd9d01b71860c58e1f3e92a187ebd60d95ae6a2a1cbfce8`.
It confirms the exact failure and no authority-bearing aggregate package. The
successful subordinate cycle artifacts are diagnostic only and cannot be
stitched, resumed, reinterpreted, or used by a replacement generation.

## Decision

Retire the complete H/G/Q generation, producer `35638724656`, publisher
`35670440520`, static observation `35670986936`, mixed preflight
`35684568600`, failed qualification `35685410662`, and their listed artifacts
through additive closed retirement policy V4. Preserve V1, V2, and V3 bytes
exactly. V4 has predecessor V3
`sha256:3064490893b1fac4a2945b5b90bec89efbfdf1bea97e0b557550950d7dae63ad`
and exact digest
`sha256:588468079ddcc6161a8cbc2bacc84d3cca2aac6e03a0325e2af72d846c9efa5d`.
All nineteen pre-effect selectors receive the same additive terminal identities.

Correct the freshness contract consistently in the formal aggregate,
production candidate reduction and continuation validation, evidence issuance,
and public v4 evidence validation:

1. Keep host boot, operation, rootfs, client-key, host-key, state, instance,
   resource, grant, receipt, status, and artifact identities globally unique
   where their existing contracts require it.
2. Compare QEMU runtime identity, live mapping, and pre/post-SSH process facts
   as `(host_boot_commitment, observation)` pairs. Equal raw host-local
   observations on different boot commitments are valid.
3. Continue to reject any repeated host boot, any repeated host-scoped pair,
   and pre/post-SSH equality within one cycle. Preserve all per-receipt lineage,
   executable, QMP, `/dev/kvm`, timing, token, key, cleanup, and zero-residue
   validation.
4. Add realistic positive fixtures with equal local values on distinct boots
   and hostile fixtures that replay the host scope or reuse the same-cycle
   pre/post process fact. The correction must not replace multi-factor
   freshness with mapping equality or weaken independent-cycle requirements.

The exact retained seven-cycle input may be used only as a local regression
fixture to demonstrate the corrected predicate. Its acceptance is diagnostic
and grants no production authority.

Establish a fresh corrected implementation H only after complete review,
focused and full tests, budget/accounting validation, protected PR checks, and
fresh exact-main checks. The corrected H must then use the existing separated
sequence: one audited producer; a reviewed governance-only G whose sole parent
is exact H; one audited publisher and one audited thirteen-member static
observation; a reviewed Q whose sole parent is exact G; one mixed preflight;
and exactly one fresh formal qualification. Any failure is terminal for that
new generation.

No prior producer, publisher, static, preflight, cycle, qualification, planning,
approval, or campaign artifact can satisfy the new chain. G remains forbidden
to change H-owned executable/runtime behavior, workflows, Dockerfiles,
ordinary tests, qualification constants, campaign, provider, or production
behavior. Q must preserve its accepted static package byte for byte.

To keep the tracked-source limit unchanged while adding this ADR and V4,
remove the five non-authorizing ADR 0091 planning shards under
`.pi/outcome-two/adr0091-plan-{ab,cd,common,ei,holistic}.md`. Accepted ADR 0091
retains the decision, the implementation and review records remain tracked,
and Git history retains the exact intermediate planning bytes. This is source
inventory retirement only and grants no deletion credit or authority.

This correction adds exact paths and makes one prospective, zero-sum line
reallocation. Move 593 lines from `local-tofu-ssm` (6,800 to 6,207) and 50
lines from `readiness-ci` (400 to 350) into `final-HGQ` (1,507 to 2,150).
The observed candidate remains below each donor high rather than pegging either
donor to observed use. Keep every byte high unchanged. The five-task tranche
therefore remains exactly 22,157 lines and 21,500,000 bytes; final-HGQ keeps
its 607-line / 1,700,000-byte pre-H cap and raises only its line-side post-H
reserve from 900 to 1,500 while retaining 3,500,000 bytes. The source limits
remain 1,564 tracked files, 34,000,000 inventory bytes, and 262,144 serialized
inventory bytes. No deletion credit applies.

## Consequences

The failed generation is terminal and permanently non-authorizing. Planning,
formal AWS IAM roles, repository role variables, approval issuance, production
execution, and Issue 42 closure remain blocked until a fresh corrected
qualification succeeds and passes independent audit.

After that audit, IAM readiness and planning still require their separate late
gates. Production R remains one workflow run, attempt, approval, batch, and
evidence generation across the existing two sequential jobs. All OIDC, STS,
deadline, cost, continuation, cgroup, signature, cleanup, recovery, evidence,
and independent zero-resource constraints remain unchanged. Stage 4 remains a
separate non-authorizing consumer of accepted Stage 2 evidence.
