# ADR 0335: Replan measured KVM custody and final corrections
- Status: Budget gate committed (`08593a43`); source implementation and review corrections present; final implementation review and local execution pending
- Scope: Governance/budget gate only; no product source or execution authority
- Reviewed input: `/tmp/cogs42-kvm-budget-replan.md`
## Baseline and decision
Baseline Q remains `8ddd4c3164bae32dbe02c67d2ee9b82eb8315a38`, tree `181128aae8617eb58c5dce743416f4f69266c02c`. Reviewed pre-gate correction HEAD was `e3c1e938f3237df468ebf266f2b1cc096ae4ba05`; ADR0334 is `044e127a`. Measured Q-relative gross usage before this gate is 8,604/12,000 lines and 416,404/1,300,000 bytes: completion 2,047; lifecycle 2,446; relay 732; integration 3,379. These are the reviewed checkpoint measurements, not measurements after this ADR's additions. The three-file Docker functional topology implementation and subsequent review corrections are present but unexecuted; final implementation review remains pending. Finding12 remains open because real KVM lacks the external generation envelope required by ADR0333.
Add this governance-only ADR as the eighth and final planned file. This supersedes ADR0334's numeric forecasts/highs, seven-file allocation and remaining-task ledger, and clarifies ADR0333 finding12's source-only tranche and later execution stop. ADR0333's path matrix, production contracts, deferred restrictions and all other stops remain unchanged. No correction, post-H, final-H, remediation or physical/conservative accounting anchor moves. **No historical gross transfers: zero lines and zero files transferred.** Existing commits gain no retrospective authority if this gate fails.
## Independent line and byte budgets

| Owner | Q baseline | New Q-relative forecast | Cumulative remediation high |
| --- | ---: | ---: | ---: |
| route | 2,023 | 0 | 2,200 |
| revocation | 2,984 | 0 | 3,000 |
| completion | 2,972 | 3,500 | 6,500 |
| lifecycle | 7,348 | 4,300 | 11,700 |
| relay | 1,953 | 2,800 | 4,800 |
| integration | 12,325 | 4,500 | 17,000 |
| total | 29,605 | 15,100 | 45,000 global |

The Q forecast endpoint is 44,705, not permission to transfer spare capacity up to the 45,000 global high. Owner highs sum to 45,200; the global 45,000 remains an independent stop. Route/revocation forecasts remain zero, including byte/mode-identical route-index regeneration. No deletion, compression, rename/copy, net-line shortcut or ownership-transfer credit is permitted.

| Independent ceiling | High | Preserved constraint |
| --- | ---: | --- |
| correction retained / global | 31,000 / 60,000 | Deploy 24,500 and workflow 6,000 unchanged |
| post-H retained / global | 19,000 / 21,000 | Deploy 1,500 and workflow 1,200 unchanged |
| physical / conservative hard | strictly below 115,000 | Preferred 90,000 advisory; mutable owners strictly below 2,000 |
| tracked files | 1,517 | 1,509 at Q + eight planned; 1,420 remediation baseline + 97 |
| source aggregate bytes | 26,000,000 | Serialized source inventory 262,144 unchanged |

Every cap applies independently, even when another cap is tighter. Deploy/workflow/mutable-owner highs stay unchanged.

| Owner | Product Q-relative byte forecast | Cumulative remediation byte high |
| --- | ---: | ---: |
| route | 0 | 350,000 |
| revocation | 0 | 220,000 |
| completion | 300,000 | 800,000 |
| lifecycle | 450,000 | 1,200,000 |
| relay | 400,000 | 700,000 |
| integration | 700,000 | 2,700,000 |
| total | 1,850,000 | 5,970,000 |

These are exact owner totals, not a new source/test/docs category split. Baseline source bytes 18,763,891 + cumulative byte highs 5,970,000 = 24,733,891, below 26,000,000. Aggregate forecast fit does not replace actual owner byte gates or later independent source-inventory implementation and serialized-size checks. Source-inventory constant synchronization and deterministic readiness regeneration were mandatory follow-up work, not performed or claimed by the original budget gate.
## Exact remaining-task ledger and review release
The 6,496 remaining gross lines at the reviewed HEAD are allocated without transfer. Governance, tests, docs, later amendments and regeneration consume these totals; they are not free.

| Owner | Remaining | Closed remaining tasks |
| --- | ---: | --- |
| relay | 2,068 | bounded helper/call-site/QMP/tests 1,400; review reserve 668 |
| lifecycle | 1,854 | mounted-snapshot/compose corrections 400; launcher/insecure acquisition corrections 450; production HTTPS/capability/live-mount tests 350; profile truncation 50; runtime schema/docs 50; review reserve 554 |
| integration | 1,121 | ADR0335/budget tests 500; source-inventory constant synchronization/readiness regeneration 100; later in-file ADR0335 execution-contract amendment and existing tests 200; product execution docs/tests 100; reserve 221 |
| completion | 1,453 | event review corrections/tests 700; telemetry/HTTPS integration 300; reserve 453 |

Any owner crossing stops and requires another reviewed gate. No reserve release before that owner's named tasks complete; release requires an explicit reviewed checkpoint identifying remaining work, task consumption, reserve use and the exact changed-since-review diff. Named-task consumption and reserve release are controlled by code review and changed-since-review checkpoints. Owner line/byte gates are mechanical; the checker truthfully enforces owner/path totals, not task purpose inferred from line diffs. Review corrections must stay within the named allocations and authorized releases; spare capacity is not transferable.
## Exact eight-file allocation
Integration new-file high becomes 87; total owner new-file highs become 97. Other highs stay route 1, revocation 0, relay 1, lifecycle 5 and completion 3. Exactly these eight paths are allocated across the entire Q-relative correction, not eight additional files in this gate:

| New path (absent from Q) | Owner |
| --- | --- |
| `dev/linux-kvm/bounded-command.py` | relay |
| `src/skills/snapshot-session-preparer.ts` | lifecycle |
| `dev/product-test/host-custody.py` | integration |
| `dev/product-test/runner.ts` | integration |
| `dev/product-test/snapshot-owner.ts` | integration |
| `docs/adr/0333-authorize-controlled-product-test-corrections.md` | integration |
| `docs/adr/0334-reallocate-measured-product-test-correction.md` | integration |
| `docs/adr/0335-replan-measured-kvm-custody-and-final-corrections.md` | integration |

Only ADR0335 is created now. No new fixture, report, restriction, schema, image or execution-gate file is implied. Existing ownership remains exact and unique, including all historical Q allocations. Tests extend existing files.
The separately authorized full-check integration correction admits only `test/aws-stage2-completion-kata-runtime.py` and `test/aws-stage2-completion-local-result.test.ts` to the product matrix as existing integration paths. Both retain their historical Q integration owner; only stale budget assertions change, with no runtime or workflow authority. Budget/test corrections use the existing integration ADR0335/budget-test allocation; source-inventory synchronization and deterministic regeneration use the existing 100-line allocation. No ceiling, new-file allocation, reserve release or historical gross transfer changes.
### Authorized custody/KVM review correction path amendment
The owner's source-only review correction adds exactly these existing paths to the product matrix, retaining their historical Q owners:

| Existing path | Owner |
| --- | --- |
| `dev/linux-kvm/qualify.sh` | relay |
| `test/egress-conformance/guest-probes/run-kvm-black-box-case.sh` | relay |
| `dev/launcher/supervisor.ts` | lifecycle |
| `test/dev-launcher-supervisor.test.ts` | lifecycle |
| `scripts/run-launcher-smoke-evidence.ts` | integration |
| `test/launcher-smoke-evidence.test.ts` | integration |

The product matrix now contains 72 paths, still exactly eight new files, including the candidate-CI fixture amendment below. No ceiling, forecast, reserve release or historical gross transfer changes. Relay changes/tests consume the bounded-helper/call-site allocation; lifecycle inventory changes/tests consume launcher acquisition corrections; matrix synchronization consumes integration budget tests, and exact inventory-consumer validation consumes product execution docs/tests. Smoke consumes destroy authority before invocation, fails on nonzero/malformed retirement and never retries after report failure. Public inventory exposes acquisition uncertainty and retirement intent independently of mutable phase and worker recovery, without conferring cleanup authority.
## Finding12: source-only tranche, no execution authority
Finding12 implementation in the later source tranche is source-only: add the bounded-command helper, convert every admitted driver/smoke/conformance guest invocation, bound QMP, reject truncation and prove behavior with portable subprocess/fault tests. It performs no Docker/KVM execution and makes no finding-closure or host-containment claim. The initial functional product-test topology is Docker-only and mechanically rejects a KVM profile, so finding12 cannot be triggered by that product scenario. Portable command bounds do not establish an external generation envelope.
**Source admission is closed now.** No exact local KVM execution authorization is issued. `dev/linux-kvm/ci-smoke.sh`, every effectful `dev/linux-kvm/driver.sh` action (including cache preparation and destroy), `dev/linux-kvm/qualify.sh`, and the direct `dev/linux-kvm/bounded-command.py` CLI deny before effects. Only the driver's pure policy renderer and imported primitives used by portable fault tests remain available. No nonce, network lease, workflow label/schedule, caller environment value or Q evidence satisfies this missing authorization. Existing workflows are unchanged and cannot execute these KVM paths. The legacy black-box entrypoint is a denial-only stub with no transport, discovery or cleanup path; lifting other gates must not re-enable it. The later amendment must replace these source stops with exact authenticated local-envelope admission at every ingress, not a boolean opt-in. This correction is not that execution gate.
Actual KVM execution remains prohibited until focused/full source reviews pass and ADR0335 is amended in an existing-file, independently reviewed local-execution gate. That later in-file amendment must specify the complete fresh protected-runner envelope then used, including:
- stop-before-exec placement for every driver/smoke/helper process and cgroup escape prevention;
- all writable paths and logs, fixed storage/quota, and exact lifetime/settlement deadlines;
- the existing non-initial network namespace and root-owned `/run/cogs-kvm-network-domain/<device>-<inode>` lease;
- preloaded image/cache identity and receipt-bound retirement.
It must use existing allocated paths or stop for another budget/file gate; no ninth file is implied. Missing prerequisites fail before effects. The present ADR is not that amendment. Docker execution also still requires the separate reviewed local-execution gate; an unexecuted topology or portable test cannot substitute for it.
## Current synchronization checkpoint
The budget gate was committed in `08593a43`; source corrections and readiness are present through `c954d817`. PR537 candidate CI exposed fixture assumptions: KVM replacement now stages outside inventoried state before atomic rename (distinct live inode; inode ABA remains possible after unlink/recreate); skills heartbeat loss arms only after successful preparation; both SSH fixture keys use bounded parse-validated retries; S5 descriptor collisions use private regular files rather than shared `/dev/null` timestamps. Admit only existing `test/aws-stage2-completion-kata-s5.py` to integration's product matrix and allocation; it has zero remediation-to-Q gross additions, so no historical ownership transfer. Compact prior-added integration test scaffolding without removing coverage to retain 4,500 gross lines; preserve all deadlines, assertions, caps and the eight-file allocation. Source-inventory limits stay synchronized and readiness is regenerated twice. These fixture corrections do not complete final implementation review or authorize execution. Finding12 remains open; Docker/KVM/AWS/provider stops and the independently reviewed local-execution gate remain pending.
The remaining product-review corrections accept Docker's cgroup-v2 swappiness `null` or integer `0` only while still checking effective `memory.swap.max=0`; retain helper leaders with pidfd `waitid(WNOWAIT)` through both final signals before reap; and fchmod/read back requested directory modes independently of umask. Portable regressions cover ordering/reuse and each executable capability-removal create/start/probe/receipt-cleanup contract. The source-only `runner.ts --capability-probes <restrictions> <candidate>` entry runs eight fresh generations, each with exactly full-minus-one capabilities and a non-authorizing custody purpose: startup and pinned authenticated SSH/SFTP outcomes are measured, not presumed failures. No probe can create a worker, grant a lease, admit evidence or pass; output follows exact-receipt settlement, and uncertainty remains failed. The ordinary run still requires the exact full set. This implements executable scenarios, not permission to execute them; all existing Docker/KVM/AWS stops remain closed.
### Final-review fix checkpoint
Final-review fixes make tool errors bind evidence; snapshot discovery uses journaled publication with no external temp; Buildx inventoried retirement removes only exact tool metadata and preserves uncertain rollback custody; FIFO nonblocking validation prevents hangs; and cross-invocation fixtures serialize ancestor mutation without weakening trusted-file validation. This checkpoint grants no execution authority; all Docker/KVM/AWS/provider and independently reviewed local-execution gates remain closed.
The follow-up to `1c859129` independently admits the actual bounded structured Bash success in runner and host (`ok` true, integer exit code zero, exact output/error-accounting shape); Pi's `isError` alone grants nothing. Hashes use the exact JSON-normalized admitted/native projection, including omission of own `usage:undefined`, with success/failure regressions through the real Bash/Pi adapter. Buildx retirement requires a descriptor-held root-owned private parent and private quarantine: rename, verify the moved inode/content, then delete only within that protected namespace. Non-root retirement and any mismatch fail closed, preserve custody, and never invoke sudo; portable root syscall models test final unlink/rmdir replacements and quarantined foreign inodes. The fixture uses a never-unlinked OS flock inode with bounded acquisition and pipe/kill release; killed-holder and serialization controls remain local-only. AST-identical statement compaction preserves every host assertion and branch within the unchanged integration ceiling. No new files, budget changes, execution authority, or Docker/KVM/AWS/provider actions are introduced.
## Historical governance-gate enforcement and validation boundary
The budget checker/tests must enforce actual Q-relative owner line+byte highs, global and every independent cap, the exact eight-file allocation, no ownership transfer/deletion credit and hostile central/attribute bypasses. Preserve raw UTF-8 added-line bytes including actual LF/CRLF, full canonical generated-line charges, ordinary untracked-file charges, and NUL/UTF-8/ordinary-file checks. Preserve isolated Git configuration/attributes, uncached index, explicit repository-transform rejection, Myers/indent/U3 patch selection and numstat cross-check; no filter, textconv, rename/copy or staged-clean-output bypass. Historical ADR0334 accounting details remain applicable.
Only this ADR, `docs/adr/README.md`, the ADR0334 supersession reference, `config/external-review-remediation-budget-v1.json`, `scripts/check-stage2-retained-lines.py` and `test/stage2-remediation-budget.test.ts` change in this governance gate. Run local budget measurement against actual current integrated usage, targeted budget tests and formatting/diff checks. No full check, readiness regeneration, source implementation, Docker/KVM execution or finding closure is claimed. The original pre-commit instruction was “Do not commit pending two independent reviews”; the gate's committed status does not establish final source implementation review. No AWS/provider/model/credential operation or authoritative H/G/Q workflow is authorized; no retirement or evidence relabeling. **Stop immediately before every AWS-facing command.**
