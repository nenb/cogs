# ADR 0309: Retire post-review H and authorize bounded corrections

- Status: Accepted
- Date: 2026-09-07
- Accepted by: the authorized repository owner/user through explicit acceptance of the bounded post-H correction plan in the implementation conversation, before implementation
- Scope: `/tmp/cogs42-posth-governance.md`, assessed at H `6bd12dcd25d877ffac03752fa0f71beeeb86a99e`; this slice implements only governance, mechanical retirement, accounting and offline guards/tests

## Decision and operational hold

Permanently retire exact H `6bd12dcd25d877ffac03752fa0f71beeeb86a99e` from selection. Supersede any unused H-specific selection permission. No producer, publisher, run or artifact identity is asserted for this H. Preserve ADR 0308's retired H `8907eba3191d07573cd84573cb0b2adddff17bd6`, G `242bbefeae5444118d9e97b46597130b509ca253`, diagnostic `34023790672`, producer `34028384783` and artifact `9988125363` as non-authorizing tombstones. ADR 0308 and earlier evidence remain historical, not rewritten or rebound.

Retirement applies to exact selected executable source/H/G/Q and authenticated artifact provenance, never merely to ancestor presence. A corrected descendant may contain retired commits in history. Missing or malformed retirement policy denies selection. Protected workflows carry literal pre-checkout mirrors of the exact policy tombstones, tested for equality; a guard loaded from the retired checkout cannot protect its own acquisition. Repeat selection checks before build/publication/grant effects. Preserve archival decoding, custody interpretation and cleanup-only settlement.

Not retired is not authorization. Keep protected-main, actor, exact reviewed constants, sole-first-created/attempt-one, authenticated custody and directional H→G→Q requirements. Unfilled authority fields remain blocked. No rollback/tag dispatch is permitted. New guards cannot retroactively patch old workflow versions or stop intentional execution of old source; protected-main and this operational hold remain necessary.

This decision grants no dispatch, producer, publisher, preflight, qualification, AWS credential/API, provider/OpenTofu, SSM, inventory generation, deployment, campaign, release, Stage 4 authority or Issue #42 closure permission. No replacement H/G/Q is assigned. No GitHub variable is changed. Fresh independent security/lifecycle/evidence review and corrected endpoint evidence are required before a later accepted freeze.

## Seven bounded closures (not claims of implementation)

Retain ADR 0308's shared contracts and default-deny boundaries. Authorize only:

1. Positive-only S3-09: expected positive fixture delta, authenticated relay observations, durable correlated intent and successful completion. Deliver only the generation public CA through existing trusted transport, verify chain/name, remove insecure curl, forward the existing session capability. Zero/missing traffic never passes.
2. Explicit aggregate Envoy envelope for outer/internal connections, H1/H2 buffers/streams, deadlines, upstream/authz circuit breakers and finite generation lifetime; review a multiplicative bound and prove pinned-runtime enforcement and client compatibility.
3. Revoke bootstrap OpenBao root and verify denial before ready; failure is terminal with exact cleanup/custody. A separate narrow short-lived orphan harness-mutation token may preserve fixture mutation, never root or broader runtime privilege during traffic.
4. Preserve the full eight-hour session plus certificate margin and rounding. Raise only fixed fixture PKI role ceiling to 9h within the existing 24h mount/CA; never clamp a requested leaf to 8h or weaken validation.
5. Fresh bounded close observers per caller, with one actual retirement owner, inherited absolute deadlines, sticky failure/uncertainty and dependency-safe release. No repeated effects or timeout-as-retirement.
6. Reject the x32 syscall bit before native seccomp dispatch, preserving exact native exceptions; update only active digest consumers and portable hostile tests. Historical accepted digests remain historical. Host ENOSYS is not filter-denial evidence.
7. Use `-serial null` after checking consumers: no guest-controlled host serial retention; retain SSH/QMP readiness and exact teardown. If serial evidence is required, stop for a reviewed byte-bounded design.

No new proxy, capability lifecycle, database, scheduler, secrets framework or cloud authority is authorized. Preserve hostile tests. Any newly discovered path requires reviewed exact allocation before editing.

## Exact allocation and measurement

`config/external-review-remediation-budget-v1.json` is the whole-file exact ownership map, including future closure files (x32 and serial included), all nine retirement workflows, eight Python guards and the preflight shell, their existing tests, and the retirement policy/helper. Existing assignments remain unchanged. No wildcard, deletion credit, transferable hunk credits or binary/ignored-input exceptions are allowed. Charge additions, replacements, moves and formatting from unchanged baseline `242bbefeae5444118d9e97b46597130b509ca253`, with rename/copy detection disabled.

| Owner | Measured H gross | New ceiling | Forecast additional reserve | Forecast endpoint |
|---|---:|---:|---:|---:|
| route | 664 | 2,200 | 450 | 1,114 |
| revocation | 737 | 1,700 | 600 | 1,337 |
| relay | 527 | 2,300 | 330 | 857 |
| lifecycle | 2,896 | 4,300 | 1,050 | 3,946 |
| completion | 1,754 | 2,600 | 0 | 1,754 |
| integration | 909 | 2,900 | 1,450 | 2,359 |
| **Total** | **7,487** | **16,000** | **3,880** | **11,367** |

Integration forecast: 350 seccomp + 1,100 retirement/governance/accounting/tests. These are forecast subceilings, not measured future closure. Byte forecasts and new-file highs remain unchanged (40 total, integration 24). The three immediate new files are this ADR, retirement data and helper. Planned integration baseline-absent paths rise from 18 to 21. Replace absent old reservations with this ADR and future `0310-freeze-remediated-H-and-authorize-control.md` / `0311-establish-remediated-Q-and-authorize-qualification.md`; do not create those future records now.

Measured at H: Stage2 physical 90,536, conservative 94,195; deploy/retained/workflow correction 21,948 / 12,055 / 4,838, global 38,841; mutable owners 1,126. Reserve at most 150 / 500 / 350 additional counted lines respectively (≤1,000 combined); forecast conservative ≤95,195 and global ≤39,841. Explicitly retain and charge the new helper/data; do not remove retained members for capacity. Keep accounting anchor `FINAL_H_REVISION` unchanged.

Retain Stage2 highs 22,300 / 13,100 / 5,500, global 40,500, strict hard `<95,900`, advisory 90,000 and strict mutable-owner `<2,000`. Retain source limits: 1,460 tracked files, 22,020,096 aggregate included bytes, 262,144 serialized inventory bytes and 4 MiB/file. H measured 1,431 tracked files, 1,428 included entries, 19,045,737 included bytes and 221,408 serialized bytes. All thirteen future v5 members remain reserved and exactly absent until Q; partial, extra or ignored v5 is rejected. Actual endpoint measurements replace forecasts in the implementation handoff; any overrun stops for reviewed adjustment.

## Historical snapshot and next decision

The assessment observed no tracked full-H literal or repository variable equal to new H. Preserve the observed repository-variable snapshot (not a fresh remote audit): implementation `229ea62bce964086726181974a6fec1c6dfd1f86`, control `821149ba4c3dbccef48694efcdb1eb29fa9fd2b9`, qualification `06188f67a9a699924d645ce8aa0e91950b6341c7`, package `7ee5d6c324363116080b528d1b912d2c123f45d7`, rootfs `de027e33312be49e5b825c0abc7e864688ae2aaa`; local/native/release authorized actors each `nenb`. Environment/organization variables and remote artifacts were not enumerated. Before any separately authorized mutation, recheck and report drift rather than overwriting unrelated bindings.

Retained source inventory Merkle `8a1f2931a6d1a131df9b5a2de0e72b198c1bfb81fe9d53f16ea8536f681800ad` binds H's bytes, not a commit or clean index. Preserve it as historical evidence; do not relabel or regenerate in this slice. Passing offline tests or ordinary CI cannot make old H selectable. Stop after local implementation, measurement and handoff; later ADR 0310/0311 require genuinely new reviewed source and observed custody, never renamed old artifacts.
