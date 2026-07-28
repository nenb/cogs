# ADR 0092: Correct ADR 0091 final-review findings before native execution

- **Status:** Accepted
- **Decision date:** 2026-07-28
- **Reviewed implementation:** `a3f529a8ffd5c7c886d5e33c88c7e03d5b86aa08`
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- **Inputs:** the five `.pi/outcome-two/adr0091-final-review-*.md` reports

## Context

Five fresh hostile reviews blocked ADR 0091 signoff. They found one root-capsule P0 and further P1–P3 defects in source admission, CLI exits, operation/result binding, common baselines, report-custodian recovery, A/B evidence, C/D primitive ownership, E sandbox observation, workflow exact-head binding, portable fault coverage, and readable security transitions.

This decision authorizes only the closed source and portable/static correction below. It authorizes no `--workflow-bound` invocation, native job, sudo/native primitive, workflow dispatch or rerun, provider, AWS, OpenTofu, deployment, campaign, production, release, or issue-closure activity.

## Decision

### 1. Root authority is independently pinned before sudo

Delete the self-signed capsule contract. The root bootstrap contains or receives through a non-caller-forgeable fixed authority the exact accepted bootstrap SHA-256 and source-set framing expected for the reviewed head. It never trusts a digest, revision, parent PID, source list, profile, or nonce merely because the same unprivileged capsule supplied it.

Before sudo, the unprivileged owner authenticates and retains exact source generations against the fixed Git head. Root verifies the independently pinned bootstrap/source identities before compiling any supplied Python. A self-consistent capsule containing different bytes rejects before code execution. The only admitted root operation is the fixed sandbox profile.

### 2. Held source admission precedes all tracked execution

Common may not compile or execute checkout-derived launcher bytes in order to authenticate themselves. A small tracked caller holds the launcher/parser/closure/schema/client generations, authenticates their Git blob identities and exact source-set digest through a separately reviewed minimal admission primitive, and only then compiles the held launcher generation. No production route reopens a tracked pathname after that admission.

### 3. Common is an operation-bound state machine

`NativeSession` records a private, immutable one-shot operation receipt only after the exact typed production operation returns. Settlement requires that receipt. Publication requires the same receipt and recomputes candidate checks/metadata from, or independently binds them to, that exact result. Skipped, failed, replayed, cross-profile, or caller-fabricated operations cannot publish pass authority.

`CleanupEvidence` stores an immutable tuple/private mapping. Callers cannot mutate observations. Common performs stable descriptor and recursive process observations with generation/identity checks and bounded repeated census; uncertain or racing state is false.

All CLI wrappers catch `Exception`, not `BaseException`, or raise `SystemExit` outside the protected body, so success remains exit zero and cleanup/failure remains nonzero.

### 4. Report publication has one durable generation custodian

The receipt/intention is durably published before the first staged named effect and records closed transaction identity: run, attempt, head, job, nonce/capability digest, workflow/common/driver/schema identities, directory generation, staged/published generation, bytes digest, size, and state.

The surviving custodian is preregistered behind a release gate before binding/listening or creating names. Parent retains pidfd/process identity until authenticated post-upload retirement and bounded reap. Every startup, write, fsync, close, rename, readback, upload-failure, cleanup, custodian-loss, and crash cut aggregates cleanup and proves either an exact retained transaction or baseline restoration.

Cleanup is authenticated by the opaque transaction capability and expected run/head/attempt identities, not a receipt-selected socket name alone. It captures the owned name without a check-then-unlink race, using an exchange/quarantine operation plus immediate descriptor-generation verification; mismatch is reversed or preserved and fails. Foreign/replaced state is never deleted. Empty owned directories are removed and parent fsynced on every safe failure path.

### 5. Metadata semantics are exact

A rejects one digest under multiple roles regardless of size and independently recomputes object, mapped-sequence, per-tool, and summary relationships.

B report metadata includes a closed summary record that binds the aggregate trusted closure, including the parser closure, as well as the existing exact gzip/zstd rows. Mask remains `63`; both outputs remain the fixed marker digest.

E policy metadata is fixed to the production-observed policy digest. Integration independently binds closure/source/output digest identities, including both fixed marker digests. Schema and common semantics reject arbitrary valid-digest substitution.

### 6. C and D prove separate real transactions

C uses an exact call-, byte-, and entry-bounded strict `getdents64` parser. The child executes the admitted fixed Python generation to prove inheritance. Parent compares exact waitid/siginfo and reap outcome; pre-exec snapshots or child-written labels do not stand for exec inheritance.

D runs independent before-release PDEATH, after-release PDEATH, and TERM-then-KILL transactions. No observation is reused for another fact. Each child is blocked and registered before effects. Planned `setsid` has a second parent-confirmed gate before descendant creation. Descendant transfer waits under a deadline, carries exact credentials, one pidfd, role/case identity, and complete immutable identity, and rejects replay/extra packets before acknowledgement. Stable recursive identity-and-edge census proves spawn-after, adoption, and retirement.

D has one aggregate failure-settlement owner that always closes gates, preserves pidfd authority, safely TERM/KILLs only revalidated identities, waits/reaps, restores and rereads subreaper state, and proves fd/process baselines.

### 7. E observes the sandbox after entering it

The sandbox result is constructed only after the process has entered the prepared root and production reads back that root's mount/no-proc/path facts. Every inner process is blocked, pidfd-owned, transferred/registered, and settled on all paths. A raw unregistered inner fork is forbidden.

### 8. Workflow and readable control flow

Eligibility and required-final jobs check out the same exact PR head SHA as A–E/integration. Merge-ref bytes never decide exact-head authority.

Security-critical code may not pack multiple fallible effects or claim derivations onto one physical line. Tests apply AST/static readable-transition checks to closure, launcher, common, and all six clients.

### 9. Portable acceptance is production-path acceptance

Portable adapters must invoke the complete production state machine above the mocked native syscall boundary. Completed result objects, token searches, or isolated helpers are non-accepting.

The declared, selected, consumed, and oracle-proved case sets must be equal for:

- held-source and root-capsule admission, including self-consistent unauthorized bytes;
- all process/fd/open/pipe/clone/pidfd/release/transition/exec/read/write/EOF/close/reap cuts;
- C strict dirents, exec inheritance, limit restoration, wait/siginfo, and close reuse;
- D three independent cases, second gate, transfer credentials/cardinality/replay, census/adoption, signals, waits, reap, and subreaper restoration;
- common stable baselines and immutable operation/cleanup receipts;
- custodian startup, durable state classification, stage/publication/upload/cleanup/custodian-loss/replacement cuts;
- all six schema/semantic goldens and isolated source/envelope/check/result/failure/cleanup/job-specific metadata mutants; and
- parsed workflow dispatch proving exact head, every failed/skipped/cancelled dependency, and no native call in ineligible contexts.

### 10. Review and execution gate

After correction, all ordinary portable/static gates run on one exact clean head. Five fresh hostile reviews—common/workflow/schema, A/B, C/D, E/integration, and holistic—must have no unresolved P0–P3.

Even clean reviews do not authorize native execution. A later accepted ADR must name the exact head, workflow/source blobs, event/attempt-one eligibility, execution count, and stop conditions. AWS remains a still-later separate boundary.

## Measured readable highs

All values are gross physical additions from `bec0a19`. Deletion, rename, generated, binary, compression, or movement credit is forbidden. Individual allowance is non-transferable.

### Trusted/portable

| Surface | High |
| --- | ---: |
| `completion_elf.py` | 320 |
| `completion_trusted_runtime_closure.py` | 2,650 |
| `completion_trusted_runtime_launcher.py` | 3,500 |
| trusted closure schema | 260 |
| Outcome Two schema registration | 220 |
| runtime-closure portable | 700 |
| mapped-closure portable | 550 |
| sealing portable | 350 |
| lifecycle portable | 1,250 |
| recovery portable | 1,100 |
| runtime-report portable | 450 |
| trusted-launcher portable | 1,650 |
| portable TypeScript wrapper | 300 |
| Outcome Two fixtures aggregate | 1,200 |
| **Trusted/portable subtotal** | **14,500** |

### Native

| Surface | High |
| --- | ---: |
| CI workflow Outcome Two addition | 350 |
| native report schema | 550 |
| native common | 1,250 |
| A driver / test | 360 / 240 |
| B driver / test | 430 / 280 |
| C driver / test | 320 / 320 |
| D driver / test | 460 / 420 |
| E driver / test | 540 / 320 |
| integration driver / test | 430 / 300 |
| native common test | 1,000 |
| **Native subtotal** | **7,500** |

The listed aggregate hard high is **22,000**. Stop for another measured ADR before exceeding any file high, subtotal, aggregate, adding a surface/dependency/action, changing report disclosure beyond the closed summary, changing trust/cleanup/job boundaries, or seeking execution.

## Consequences

The correction is larger, but the resulting evidence authority is explicit: trusted bytes execute only after independent admission; root cannot accept a self-signed capsule; each job proves its own production transaction; common cannot publish caller claims; cleanup retains exact object/process authority through upload and crash recovery; and portable tests fail when any security branch is bypassed.
