# Outcome 2 capability tests — second exact-head hostile review

**Reviewed implementation head:** `ab578313c50f52768003fa3416c514627ba1946d`
**Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`
**Authorities:** accepted ADR 0087, accepted ADR 0088, the five first capability reviews, and the exact five capability implementation surfaces.
**Disposition:** review only. No capability workflow or production path was executed; the portable/hostile tests invoked no sudo, namespace, mount, proc `map_files`, seccomp, KVM, `close_range`, `O_TMPFILE`, network, container, provider, or cloud effect.

## Verdict and attempt safety

**BLOCK — 5 P1, 3 P2, and 2 P3 findings remain.**

**Attempt safety: NOT SAFE.** The exact head has no outer recovery supervisor, does not establish the required complete baselines or exact cleanup authority, can start executable children before registration, and still lacks production-path fault qualification. A worker/interpreter crash or supervisor loss can therefore strand or leave uncertain an effectful case. Separately, ADR 0087/0088 still supplies no named exact-head/event/blob approval for an attempt. Do not apply the label, dispatch, rerun, or otherwise execute the capability workflow.

## P0

No findings.

## P1

### P1-1 — The required outer recovery supervisor and pre-release child lifecycle are still absent

**Lines:** `scripts/runner-capability-probe.py:65`, `238-334`, `1185-1194`, `1461-1480`.

`main()` calls the effectful `probe_linux()` in the only long-lived process. That same process sets itself as subreaper, owns the module-global `ACTIVE_LEDGER`, performs all cases, and is its own exception cleanup authority. There is no fixed outer supervisor plus effect worker. `Ledger.run()` also calls `subprocess.Popen()` before `register_child()` and has no parent release gate, so fixed Python, unshare, and sudo/root transitions can begin before pidfd/start/session registration and revalidation.

`SIGKILL`, a fatal interpreter failure, or job timeout therefore removes the only ledger, deadline enforcer, subreaper, and cleanup process. The child-side PDEATH setting reduces some descendants' lifetime but does not supply the required outer recovery/reap authority, and sudo/root transition is already live before parent registration. This leaves the first driver P1-1/P1-3 and holistic lifecycle finding unresolved.

### P1-2 — Baselines and cleanup authority remain partial and can leave unregistered names or inexact process/object cleanup

**Lines:** `scripts/runner-capability-probe.py:199-224`, `238-292`, `1117-1167`, `1185-1188`, `1238-1248`.

The supervisor captures only an fd snapshot and `generation(os.stat("."))`. It does not capture the required owned-child/descendant, mount-table, namespace-identity, private-name-root, exact checkout porcelain, or registry baselines before effects. `children_reaped`, `mounts_gone`, and `temporary_names_gone` still begin true; final checkout validation is only a cwd inode-generation comparison.

Process signaling uses a re-read PID/start/session followed by `killpg`, not the retained pidfd plus expected executable/process-group identity, leaving a check/signal race. Private names are created and then `stat`ed/registered: failure between `mkdir` and registration leaves a name that cleanup deliberately does not own. Temporary-file cleanup unlinks fixed `published` by name without authenticating the linked generation, and mount cleanup remains pathname/category based inside a batched child rather than retained owner-namespace authority and full baseline comparison.

A safe incomplete report does not cure residue or foreign-object risk. The first driver P1-2/P2-1 and holistic cleanup finding are unresolved.

### P1-3 — Production semantics still accept impossible complete reports and copy downstream facts into unrelated operations

**Lines:** `scripts/runner-capability-probe.py:737-758`, `1180-1183`, `1214-1233`, `1257`, `1288-1382`.

Independent mutation against the exact production `validate_report()` accepted all of these while the base report remained `outcome="complete"`:

- `sudo.noninteractive=unsupported/errno=null`, although null-errno unsupported is permitted only for a proved absent fixed object;
- `sudo.noninteractive=denied` while both sudo close-from operations remain `ok`;
- `sudo.noninteractive` blocked by itself, creating a prerequisite cycle;
- combined `proc_mount=denied` while child proc postconditions remain observed;
- `capability_sets_zero=false` for the post-drop child-owned-proc case; and
- `first_open_failure=ok` with fewer opened than selected mappings.

The driver additionally reports combined `proc_mount` by copying `before.maps_read`, not by recording the mount operation. `Ledger.run()` maps any nonzero child exit to `mismatch`, even when no successful syscall plus exact false postcondition was observed. Internal setup failure can therefore be copied or collapsed rather than represented as a distinct prerequisite and blocked dependent operation.

This leaves the schema P1-2/P1-3 and holistic semantic findings unresolved. Green schema shape checks do not close these relationships.

### P1-4 — The scripted adapter is a detached toy, not the production state/syscall/process boundary

**Lines:** `scripts/runner-capability-probe.py:1407-1459`; `test/runner-capability-probe.test.ts:692-839`.

`ScriptedAdapter`/`ScriptedOwner` model six abstract strings and are not used by `Ledger`, `probe_linux`, tool resolution, child creation, deadline handling, private-name/mount cleanup, or report production. The TypeScript suite contains no reference to those production owners or operations. The asserted 12 acquisition and 6 cleanup cuts therefore exercise only the toy owner.

The independent guard confirmed the self-test's narrow `real.effects=0` claim: it performs no prohibited real effect. That is useful but not the required evidence. It does not inject open/dup/pipe/pidfd/fork/read/write/exec/readiness/PDEATH/status/TERM/KILL/wait/reap faults, production deadline cuts, identity reuse, symlink generation drift, mount/name replacement, baseline failures, simultaneous cleanup errors, or fresh outer-supervisor recovery through production control flow.

The first tests P1-1 and holistic P1-4 findings remain unresolved.

### P1-5 — Irreversible cases are still batched and forked cases do not install the fixed socket/io_uring filter before case work

**Lines:** `scripts/runner-capability-probe.py:161-180`, `344-401`, `619-653`, `1185-1237`.

`child_boundary()` closes descriptors, clears environment, changes cwd, and redirects stdio, resolving that portion of the earlier child-isolation finding. It does not install the fixed filter. `fork_case()` then releases tmpfile, mount, namespace, descriptor-limit, seccomp, and KVM functions directly. The filter constants are used only by selected exec helpers.

`mount_namespace_batch()` also performs a mount namespace observation and then a second namespace plus tmpfile and multiple O_PATH/mount cases in one child; low and high close-range cases likewise share one child. A prior irreversible result can alter a later case's setup, contrary to the dedicated-case/no-contamination requirement. The holistic P2-1 isolation finding is only partially resolved and is attempt-blocking under ADR 0088's strengthened child contract.

## P2

### P2-1 — The credential gate still admits prohibited credential and askpass configuration, and the workflow suite has no executable Git challenges

**Lines:** `.github/workflows/outcome-two-runner-capability.yml:46-62`; `test/outcome-two-runner-capability-workflow.test.ts:40-58`, `115-140`.

The gate now rejects the two original bypasses: unscoped `http.extraheader` and a credential-bearing push URL. It still rejects only `credential.*.helper`; it does not reject every `credential.*` setting, `core.askPass`, or nonempty `GIT_ASKPASS`/`SSH_ASKPASS` as ADR 0088 requires.

An independent temporary-repository challenge showed the exact gate **accepted** `credential.username`, `core.askPass`, and nonempty Git/SSH askpass variables. The same challenge confirmed unscoped extraheader and credential-bearing push URL are now rejected, without printing canary values.

The workflow test performs only source regex/mutation checks. It creates no temporary Git repository and executes no clean or hostile credential sub-gate, so the required canary-safe executable cases are absent.

### P2-2 — Static workflow mutation coverage is incomplete and does not parse the actual YAML step sequence

**Lines:** `test/outcome-two-runner-capability-workflow.test.ts:15-112`, `119-140`.

The current workflow text has exactly three visible six-space step entries, one pinned checkout action, and the expected order. The test still counts a regex rather than parsing the YAML sequence. Its hostile matrix has eight replacements and does not independently add and reject every required unnamed `uses`, nested/local action, second checkout, `always()`, `continue-on-error`, secret context, cache/summary path, heredoc program, package/network command, retry, and fallback mutation.

The former unnamed-step blind spot is narrowed for the current indentation, but ADR 0088's structural mutation contract is not met.

### P2-3 — Child record parsing and final tool-generation authentication are not strict at the authority boundary

**Lines:** `scripts/runner-capability-probe.py:344-401`, `413-461`, `737-758`, `895-900`.

All internal parsers use ordinary `json.loads`, which accepts duplicate keys and noncanonical encodings; they do not re-encode byte-identically or reject trailing/noncanonical forms as required for the closed child grammar. Tests exercise canonical public output but do not inject hostile production child records.

For a nonsymlink final tool component, `resolve_fixed_tool()` policy-checks an `O_PATH|O_NOFOLLOW` `probe`, closes it, then reopens the pathname. The final probe generation is not retained in `chain` and is never compared with the reopened fd. A final-object replacement in that interval can become the accepted starting generation if it remains stable for the later second walk. The required first held generation and replacement fault matrix are therefore incomplete.

## P3

### P3-1 — Schema numeric domains still disagree with ADR 0088 and the production validator

**Lines:** `schemas/runner-capability-probe-v1alpha1.json:120-123`; `scripts/runner-capability-probe.py:1079-1084`, `1294`; `test/runner-capability-probe.test.ts:560-563`.

ADR 0088 requires `run_attempt` to be exactly integer 1 and PR number to be at most 2,147,483,647 everywhere. The schema still permits attempts 1–255 and PR numbers through 9,999,999,999. Full AJV mutation of the canonical fake report accepted `run_attempt=2` and `pull_request_number=2147483648`, while production rejects both. The test checks only 256 and 10,000,000,000, preserving the mismatch. The first schema P3-1 finding is unresolved.

### P3-2 — The exact reviewed head rewrites retained first-review inputs outside the five correction surfaces

Commit `ab57831` changes four retained `.pi/outcome-two` first-review/gate files solely to remove Markdown trailing spaces. ADR 0088 explicitly chose not to rewrite that retained review history and restricted implementation correction to the five capability surfaces. This does not change executable bytes or line accounting, but it is an exact-head provenance/scope deviation that should be resolved or explicitly accepted before binding a later approval.

## Prior-finding verification

| Prior finding(s) | Second-review disposition |
| --- | --- |
| Driver P1-1; holistic lifecycle portion of P1-2 | **Unresolved:** P1-1. No outer supervisor; executable child can start before registration. |
| Driver P1-2; driver P2-1; holistic cleanup portion of P1-2 | **Unresolved:** P1-2. Only fd/cwd baselines; incomplete identity-bound cleanup. |
| Driver P1-3 | **Unresolved:** P1-1/P1-2. A 20-second reserve exists, but not every effect is gated/bounded and supervisor loss remains fatal. |
| Driver P2-2 root component | **Resolved:** `/` is now checked for UID 0 and group/world non-writability. |
| Driver P2-3 child output | **Resolved for output:** child stdout/stderr are redirected/captured; fixed-filter isolation remains unresolved in P1-5. |
| Schema/workflow P1-1 UID/GID disclosure | **Resolved:** only categorical map results cross the helper pipe/report; old keys are schema-rejected. |
| Holistic P1-1 source/envelope equality | **Resolved:** no `github.sha == event_merge_sha`; golden identities are distinct. |
| Schema P1-2/P1-3; holistic P1-3 | **Unresolved:** P1-3 production mutation acceptances. |
| Schema P2-1 seccomp/proc fields | **Resolved in part:** query values are nullable and proc distinction is measured; broader proc coupling remains in P1-3. |
| Schema P3-1 numeric domains | **Unresolved:** P3-1. |
| Tests P1-1/P1-2; holistic P1-4 | **Unresolved:** P1-4; independent semantics also miss accepted production states in P1-3. |
| Tests/workflow over-high findings | **Resolved by ADR 0088 and current accounting:** all five rows and aggregate are within the corrected highs. |
| Tests P2-1 unnamed fourth step | **Partially resolved:** current regex counts three visible entries, but no YAML parse/full mutation matrix; P2-2. |
| Tests P2-2 optimized rejection | **Resolved:** both optimized self-test and independently checked optimized workflow mode reject with exit 2 and empty output. |
| Tests/workflow diff-check findings | **Resolved:** exact five-surface, correction-commit, and full predecessor diff checks pass. |
| Workflow P2-1 unscoped extraheader/push URL | **Resolved narrowly:** both reject; the strengthened ADR 0088 credential contract remains open in P2-1. |
| Holistic P2-1 child cwd/environment/fds/output/filter | **Partially resolved:** cwd, environment, descriptors, and stdio are closed; fixed pre-case filtering remains open in P1-5. |

## Line highs

Gross physical additions from `bec0a19b0b984f88ab9c2effc5059f3737915caa`:

| Exact surface | Gross added | ADR 0088 high | Headroom | Result |
| --- | ---: | ---: | ---: | --- |
| `.github/workflows/outcome-two-runner-capability.yml` | 86 | 120 | 34 | within |
| `schemas/runner-capability-probe-v1alpha1.json` | 637 | 700 | 63 | within |
| `scripts/runner-capability-probe.py` | 1,488 | 1,900 | 412 | within |
| `test/runner-capability-probe.test.ts` | 852 | 900 | 48 | within |
| `test/outcome-two-runner-capability-workflow.test.ts` | 141 | 160 | 19 | within |
| **Aggregate** | **3,204** | **3,780** | **576** | **within** |

No row borrows headroom from another. The exact five surfaces were absent at the predecessor, so these gross additions equal their physical line counts.

## Validation and independent hostile commands

All required retained commands were run at reviewed head `ab57831`:

- `/usr/bin/python3 -I -B scripts/runner-capability-probe.py --self-test` — **PASS**, exit 0, 662 stdout bytes, empty stderr; reports 12 toy acquisition cuts, 6 toy cleanup cuts, `real.effects=0`, repeatability 2.
- `/usr/bin/python3 -I -B -O scripts/runner-capability-probe.py --self-test` — **PASS (required rejection)**, exit 2, empty stdout/stderr.
- Independent `-O ... --workflow-bound` — **PASS (rejected before effects)**, exit 2, empty stdout/stderr.
- `npx --no-install tsx --test test/runner-capability-probe.test.ts test/outcome-two-runner-capability-workflow.test.ts` — **PASS**, 7/7.
- `npm run schemas` — **PASS**, 15 schemas.
- `npm run format:check` — **PASS**, 234 files.
- `npm run typecheck` — **PASS**.
- Exact ADR 0088 five-surface `git diff --check ...` — **PASS**.
- `git diff --check HEAD^..HEAD` — **PASS**.
- Full `git diff --check bec0a19...HEAD` — **PASS**.
- Independent production-validator mutation script — **FAIL contract**, accepted all six impossible states listed in P1-3.
- Independent AJV numeric-bound mutations — **FAIL contract**, accepted attempt 2 and PR 2,147,483,648.
- Independent temporary-Git credential challenges — **FAIL contract** for generic credential, core askpass, and environment askpass; **PASS** for rejecting the two original extraheader/push-URL bypasses.

Green retained checks are real but insufficient because the missing production adapter and incomplete independent matrices do not exercise the unsafe branches.

## Stop decision

Do not attempt the observation. Resolve every P1–P3, rerun the full portable/static and independent hostile matrix at one clean exact head, obtain fresh hostile sign-off, and then obtain the separately named exact-head/blob/event/attempt-1/public-log approval. No finding or green command here authorizes production or native work.

CAP-R2-TESTS COMPLETE
