# ADR 0334: Reallocate measured product-test correction
- Status: Reviewed measured replan; governance implementation pending two independent reviews and commit
- Scope: Governance/budget gate only; no further product source or execution authority
- Reviewed input: `/tmp/cogs42-measured-budget-replan.md`
## Measured replan
**Superseded budget and remaining-task ledger:** [ADR0335](0335-replan-measured-kvm-custody-and-final-corrections.md) replans the correction to 15,100 Q-relative gross lines, revised independent line/byte highs and exactly eight new files. The numbers and seven-file allocation below remain historical. ADR0335 preserves ownership and execution stops, limits finding12's implementation tranche to source-only work, and requires a later independently reviewed in-file execution-contract amendment before actual KVM execution. Its governance implementation remains pending two independent reviews and commit; no source or execution authority is added by this reference.
Baseline remains Q `8ddd4c3164bae32dbe02c67d2ee9b82eb8315a38`. Governance commit is `aaf200fdcb7b0ca09241790f660c68142accf9de`. Integrated source commits currently implement bounded events, telemetry default fetch, production mounted-snapshot verification/zero-integration admission, and generation-bound launcher/KVM/insecure custody.
Measured Q-relative gross additions after integration are 5,870/6,000: completion 2,047/1,200, lifecycle 2,446/2,200, relay 732/900, integration 645/1,700. The global total happens to fit but two independent owner forecasts fail; no deletion or compression credit is permitted. Remaining required work—bounded KVM helper, three-file product-test owner/topology, integrated tests, review corrections and deterministic readiness regeneration—cannot fit the remaining 130 lines or relay remainder.
Before further source work, add `docs/adr/0334-reallocate-measured-product-test-correction.md`, update the ADR index, budget config/checker and exact budget tests. This is the seventh and final new file allocated to the correction unless another reviewed gate says otherwise. It grants no runtime or AWS authority.
Measured revised Q-relative forecasts/highs:

| Owner | Q baseline | New Q-relative forecast | Cumulative remediation high |
| --- | ---: | ---: | ---: |
| route | 2,023 | 0 | 2,200 |
| revocation | 2,984 | 0 | 3,000 |
| completion | 2,972 | 3,000 | 6,000 |
| lifecycle | 7,348 | 3,800 | 11,200 |
| relay | 1,953 | 1,600 | 3,600 |
| integration | 12,325 | 3,600 | 16,000 |
| total | 29,605 | 12,000 | 42,000 global |

Independent ceilings: correction retained/global 28,000/56,000; post-H retained/global 16,000/18,000; hard conservative 112,000; tracked files 1,516; source bytes 25,000,000; serialized inventory unchanged. Deploy/workflow and mutable-owner ceilings remain unchanged. Integration new-file high becomes 86 and total owner new-file highs become 96: Q has 89 and seven planned files yield 96. Product-test correction exact new-file list becomes the original six plus ADR0334.
The remaining 6,130 gross lines are allocated without transfer:

| Owner | Remaining | Closed remaining tasks |
| --- | ---: | --- |
| completion | 953 | event review corrections 350; telemetry/default transport tests 150; event/consumer tests 300; correction reserve 153 |
| lifecycle | 1,354 | mounted-snapshot/compose corrections 400; launcher/insecure acquisition corrections 450; production HTTPS/capability/mount tests 350; runtime schema/docs 50; reserve 104 |
| relay | 868 | bounded-command helper 260; driver/ci/harness call-site conversion 180; helper/driver tests 260; QMP bounds 70; reserve 98 |
| integration | 2,955 | ADR0334/config/checker/budget tests 600; host-custody 450; snapshot-owner 350; product runner 850; integrated test additions 350; readiness regeneration 100; review corrections 100; reserve 155 |

Crossing any owner remainder or consuming a reserve before its named tasks complete stops source work and requires another reviewed gate. The 100-line regeneration forecast remains included in integration.
Gross-byte forecasts also expand explicitly. Product-correction Q-relative byte forecasts are completion 250,000, lifecycle 350,000, relay 150,000 and integration 550,000 bytes (1,300,000 total). Current remediation-relative gross added-line bytes measured at integrated HEAD are route 96,627, revocation 114,977, relay 128,185, lifecycle 396,105, completion 207,529 and integration 1,816,876; Q integration alone is 1,763,126 because canonical generated evidence is charged at full line bytes. Overall cumulative owner byte ceilings therefore become route 350,000, revocation 220,000, relay 550,000, lifecycle 1,050,000, completion 700,000 and integration 2,500,000 bytes (5,370,000 total). Baseline 18,763,891 plus 5,370,000 is 24,133,891, below a revised 25,000,000 aggregate source ceiling. These remain gross forecast gates, not current net-size measurements. Current aggregate source is 20,972,176 bytes. The later source-inventory implementation-limit synchronization and deterministic regeneration remain mandatory and can still fail independently.
Q-relative owner gross line/byte checks, global 12,000, exact seven-file inventory, owner/path uniqueness, no historical transfers, central invocation and isolated owner/global/hard overrun mutants remain mandatory. Existing source commits receive no retrospective authority if any gate fails. After this governance gate passes two independent reviews and is committed, remaining source work may continue. Docker/KVM product-test execution still requires a separate reviewed local-execution gate. No H/G/Q workflow or AWS operation is authorized.
## Exact inventory and enforcement
This supersedes only ADR0333's numeric budget forecasts/highs and six-file allocation. Its existing path matrix, original accounting anchors, production contracts, deferred restrictions and execution stops remain unchanged. No historical gross transfers: zero lines and zero files transferred. ADR0333's historical numbers remain labeled as superseded, not rewritten as earlier authority.

| New path (absent from Q) | Owner |
| --- | --- |
| `dev/linux-kvm/bounded-command.py` | relay |
| `src/skills/snapshot-session-preparer.ts` | lifecycle |
| `dev/product-test/host-custody.py` | integration |
| `dev/product-test/runner.ts` | integration |
| `dev/product-test/snapshot-owner.ts` | integration |
| `docs/adr/0333-authorize-controlled-product-test-corrections.md` | integration |
| `docs/adr/0334-reallocate-measured-product-test-correction.md` | integration |

The revised byte forecasts are exact owner totals, replacing the inherited source/test/docs breakdown without inventing an unreviewed category split. Route/revocation Q-relative byte forecasts remain zero. The checker independently pins all totals and measures actual raw gross added-line bytes relative to Q and the original remediation anchor: full UTF-8 added-line bytes including actual LF/CRLF, no deleted-byte subtraction, rename/copy/textconv credit or untracked-file omission. Patch selection uses the historical default Myers/indent heuristic and three context lines, cross-checked against numstat from the same invocation (Q-relative `src/api/server.ts`: 560 added lines / 21,177 bytes). Git accounting runs under isolated configuration with global/system/info attributes excluded, rejects explicit repository filter/diff/text/eol/crlf/ident/working-tree-encoding attributes, and rebuilds an uncached index so previously staged clean-filter output cannot conceal raw worktree bytes. Changed tracked and ordinary files retain UTF-8, NUL and ordinary-file validation. Canonical one-line inventories incur the full added line's bytes. Aggregate forecast fit does not replace any owner gate or the later independent source-inventory implementation and serialized-size checks.
Correction deploy/workflow remain 24,500/6,000; post-H deploy/workflow remain 1,500/1,200. Hard physical and conservative counts remain strictly below 112,000, mutable owners strictly below 2,000, preferred 90,000 advisory. Serialized source inventory remains 262,144 bytes. The Q forecast endpoint is 41,605, not permission to transfer spare owner capacity up to the 42,000 global high.
Only this ADR, `docs/adr/README.md`, necessary ADR0333 references, `config/external-review-remediation-budget-v1.json`, `scripts/check-stage2-retained-lines.py`, and `test/stage2-remediation-budget.test.ts` change in this gate. Run local budget, targeted budget tests and formatting/diff checks; claim no full check, readiness regeneration, product-test success or finding closure. Do not commit before lead review. No further product source, Docker/KVM execution, workflows, retirement or AWS operations. Stop immediately before every AWS-facing command.
