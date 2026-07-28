# ADR 0093: Close remaining native-qualification authority gaps

- **Status:** Accepted
- **Decision date:** 2026-07-28
- **Reviewed head:** `3846383f0d88c190226356ca9aeeeda402943aaa`
- **Inputs:** nine `.pi/outcome-two/adr0092-review-*.md` reports
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`

## Context

Parallel ADR 0092 review found that the implementation is substantially closer but still unsafe to execute natively. The root pin and ambient admitted entry remain caller-selectable; common can reread caller metadata rather than bind its immutable operation receipt; the durable cleanup transaction has authentication and race gaps; C/D/E production paths and complete portable corpora remain incomplete; and the launcher CLI converts success to failure.

## Decision

Authorize only the following source and portable/static correction. Native, sudo, workflow dispatch/rerun, provider, AWS, OpenTofu, deployment, campaign, production, release, and issue-closure execution remain forbidden.

1. **Independent authority is not a caller argument.** Remove ambient `invoke_fixed_admitted_operation` authority. The fixed trusted bootstrap is the only operation issuer. It authenticates the exact reviewed source/client generations against a separately fixed Git head before tracked execution. The root bootstrap pin is fixed outside capsule-controlled bytes and outside caller-rendered command text. A self-consistent unauthorized source set cannot select its own pin.
2. **Operation receipt is the report source.** Common stores the exact immutable typed result and derives checks and metadata from it once. Drivers may report a failure phase/diagnostic but cannot provide independent pass checks or a second mutable metadata reading. Every A/B/C/D/E/integration report is reconstructed and validated from the private receipt.
3. **Baseline generations are exact.** Descriptor observations bind descriptor number, stat generation, flags, and stable repeated enumerations. Recursive child observations bind PID/start/executable/edges under repeated stable census. Racing or uncertain observations are false.
4. **Upload cleanup binds bytes and capability.** The durable intent records uploaded report digest/size/generation. The cleanup capability is never written in recoverable receipt plaintext. Cleanup receives it over retained private authority, verifies run/head/attempt/job and uploaded bytes, and retires/reaps the exact custodian. Exchange/quarantine operations use retained directory and generation authority; every crash cut is classified and recoverable without a check-then-unlink/rmdir race.
5. **Custodian and tool children are preregistered.** Every returned fd is leased before the next fallible effect. Every child is blocked until pidfd/process identity is retained. Secondary pidfd or transfer failure has a creator-owned gated cleanup path.
6. **C exact bound.** Permit 32 non-empty bounded `getdents64` calls plus a separately bounded EOF call. Portable cases drive every real production cut and prove exec causality, exact wait/siginfo/reap, limits, and cleanup.
7. **D preregisters before lifecycle effects.** Descendants remain behind the second gate until exact pidfd/credentials/role/case/identity transfer and outer registration. Siginfo validates exact PID/UID/code/status. Complete before-release, after-release, and TERM/KILL cases have aggregate failure settlement.
8. **E inner authority is transferred before effects.** The inner process remains blocked until the outer surviving owner has exact pidfd/identity authority. Root source authority is independently pinned. Portable cases execute the complete sandbox owner above mocked syscalls and cover every transfer, chroot/readback, mount, exit, reap, namespace, and restoration cut.
9. **Workflow acceptance is parsed and causal.** Tests parse workflow structure, dispatch real CLI entry points with effect sentinels, and prove exact-head checkout and all failed/skipped/cancelled dependency outcomes.
10. **Portable ledgers are causal.** Declared, selected, consumed, and oracle-proved case identities are equal. An unrelated early failure does not satisfy a later cut. Complete A/B/C/D/E/integration/common/custodian production state machines run above mocked native primitives; completed result fabrication and token-only tests are non-accepting.
11. **Readable transitions are enforced.** AST/static checks cover closure, launcher, common, and all six clients and reject semicolon-packed effects, unlabelled positional security claims, and allocations without immediately visible adoption/recovery.
12. **CLI success remains success.** `SystemExit(0)` is not caught as failure in launcher, common, or clients.

After correction, ten parallel exact-head reviews must find no P0–P3. A later execution ADR may then authorize exactly one attempt-1 Linux run of Jobs A–E and two thin integrations. AWS remains separate.

## Revised highs

Gross physical additions remain counted from `bec0a19`; deletion/movement gives no credit.

- closure: **3,100**
- launcher: **4,700**
- native common: **1,900**
- native schema: **700**
- schema registration: **300**
- workflow Outcome Two addition: **400**
- runtime-closure portable: **1,000**
- mapped portable: **700**
- lifecycle portable: **1,800**
- recovery portable: **1,500**
- trusted-launcher portable: **2,300**
- runtime-report/sealing portable: **550 / 450**
- portable wrapper: **400**
- fixtures aggregate: **1,700**
- common focused test: **1,500**
- each native driver: A **420**, B **500**, C **380**, D **520**, E **620**, integration **500**
- each focused test: A/B **350**, C **450**, D **600**, E **500**, integration **400**
- trusted/portable subtotal: **19,000**
- native subtotal: **10,000**
- listed aggregate: **29,000**

Stop for another ADR before exceeding a high, adding a dependency/surface/action, changing trust/job/cleanup/report boundaries, or seeking native/cloud execution.
