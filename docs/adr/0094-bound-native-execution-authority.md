# ADR 0094: Bound native diagnostics and defer final-evidence authority

- **Status:** Accepted
- **Decision date:** 2026-07-29
- **Decision owner:** Nick Byrne
- **Accepted by:** Nick Byrne's explicit instruction to prepare this bounded non-AWS execution decision.
- **Architecture predecessors:** ADR 0093 and, where non-conflicting, ADRs 0087–0092.
- **Current exact implementation head observed:** `cc7179449dd5d0fa222fbb141b234bf48ac6da75`.
- **Last historical run in scope:** GitHub Actions run `30461497437`, attempt 1.
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`.

## Context

ADR 0093 authorized source and portable/static correction only. It explicitly prohibited native execution, sudo, workflow dispatch/rerun, and integration execution. Native dispatches nevertheless followed the merge of the ADR 0093 implementation. None reached the required all-green result. Integration never ran because Job B never passed.

The latest native attempt, run `30431675509` at exact main head `cc7179449dd5d0fa222fbb141b234bf48ac6da75`, passed Quality, C1, A, C, D, and E. Job B failed in the admitted launcher with the bounded diagnostic `runtime-launcher-exception-File`; report upload did not occur, report cleanup failed because no publication existed, integration was skipped, and the required result failed.

Historical Quality jobs were not static-only. They invoked `deploy/aws-feasibility/validate.sh`, which installed OpenTofu, ran non-deploying `tofu init -backend=false` and `tofu validate`, and could download provider plugins into the configured cache. Those operations contacted no AWS API and performed no deployment as designed, but they were real OpenTofu/provider execution. This ADR therefore does not claim that no OpenTofu or provider activity occurred. Those Quality results and downloads grant no AWS, provider, deployment, or final-evidence authority.

Runs `30429782506`, `30430763715`, and `30431675509` also measured a narrower environmental fact. GitHub's protected default-branch runner accepted this exact Job B privilege transition and reached the tracked launcher:

```text
/usr/bin/sudo -n --close-from=3
  /usr/bin/prlimit --nofile=65536:65536 --
  /usr/bin/setpriv
    --reuid=<authenticated-runner-uid>
    --regid=<authenticated-runner-gid>
    --clear-groups
    --inh-caps=+sys_admin
    --ambient-caps=+sys_admin
  /usr/bin/env -i <fixed-allowlisted-environment>
  /usr/bin/python3 -I -B <fixed-driver> --workflow-bound
```

That observation says only that the measured wrapper was admitted and entered tracked code. It does not prove Job B, sandboxing, cleanup, integration, or evidence authority. The earlier `--keep-caps` spelling failed on run `30428012940` and is rejected.

A bounded architecture is now required to stop the unreviewed correction/dispatch loop and admit only the minimum remaining diagnostic opportunity. Final-evidence execution is deferred to a later accepted exact-head ADR.

## Decision

### 1. Complete historical disposition

Every run listed below is immutable history. A success token from an individual job remains a **non-authoritative diagnostic observation only**. No listed run or artifact may be combined, replayed, promoted, or cited as Outcome 2 qualification, final evidence, trusted closure authority, production authority, or issue-closure authority.

#### 1.1 Earlier Stage 2 and native-envelope observations

Runs `30156175807`, `30156593245`, `30157183403`, `30159926371`, `30180567774`, `30180567797`, `30192739504`, `30194550977`, `30199795587`, `30217525176`, and `30218838605` retain only the historical disposition already recorded by ADRs 0047–0065 and ADR 0087. In particular, `30218838605` remains Outcome 1 rootfs history and is not Outcome 2 authority.

The following 49 PR-triggered native-runtime-preflight runs are also diagnostic history only. Entries are `run@source-prefix` with GitHub attempt and conclusion. Attempt-2 entries are expressly rejected as evidence. Cancelled entries establish no absence or cleanup claim.

| Runs | Runs | Runs | Runs |
| --- | --- | --- | --- |
| `30258875115@a7914db6` (a1, failure) | `30259342649@51a9d85f` (a1, failure) | `30259812584@eced0713` (a1, failure) | `30260240388@ee619001` (a1, failure) |
| `30260537349@82be5273` (a1, failure) | `30260964091@48414a2e` (a1, cancelled) | `30261000448@66f89ab3` (a1, failure) | `30261305894@d87ff2e3` (a1, failure) |
| `30264433025@dea50411` (a1, failure) | `30264951020@0c74a0bf` (a1, cancelled) | `30265013266@e4650ab1` (a1, failure) | `30267205781@62b5de65` (a1, failure) |
| `30267569840@a5ff639c` (a1, failure) | `30268105408@d53b1165` (a1, failure) | `30270026904@509d49af` (a1, failure) | `30270555801@e336ea0d` (a1, failure) |
| `30271099348@2f9a3a87` (a1, failure) | `30271502278@2c4db02d` (a1, failure) | `30272064707@17839c04` (a1, failure) | `30272836574@192b7232` (a1, failure) |
| `30273214144@058e8736` (a1, failure) | `30273723176@3dd2b0ec` (a1, failure) | `30275086069@ea800bec` (a1, failure) | `30275576514@31448903` (a1, failure) |
| `30275927878@bed2d05b` (a1, failure) | `30277333237@249c66c6` (a1, failure) | `30277864818@9cb67fda` (a1, failure) | `30279366022@f010ac8f` (a1, failure) |
| `30279739250@c59ce866` (a1, failure) | `30280107052@7d803ece` (a1, failure) | `30280479115@b8cd2cc2` (a1, failure) | `30280897936@71285791` (a1, failure) |
| `30282124718@d8d3a05f` (a1, failure) | `30282510246@0968fa44` (a1, failure) | `30283040715@69404a1a` (a1, failure) | `30283415791@f5da9ac6` (a1, failure) |
| `30283772032@a37ad4d8` (a1, failure) | `30284551330@5607f71b` (a2, cancelled) | `30285826981@286b7824` (a1, failure) | `30286246316@7021a55d` (a1, failure) |
| `30286623708@7282309a` (a1, failure) | `30287673764@4b508950` (a2, failure) | `30288485615@0d5d9c49` (a2, failure) | `30289249416@35c13902` (a1, failure) |
| `30289588414@86e6974d` (a1, failure) | `30290892652@cbbb4fb6` (a1, failure) | `30291262603@d9ef36e3` (a1, failure) | `30292309051@e1e007fb` (a1, failure) |
| `30292638819@d96b58ab` (a1, failure) |  |  |  |

#### 1.2 Runs after ADR 0093's execution prohibition

The following 54 `workflow_dispatch` runs occurred after the prohibition. This ADR does **not** retroactively authorize them. It explicitly classifies every one as a non-authoritative diagnostic observation. Run `30378350127` failed closed at eligibility and supplies no native fact. Every other partial pass is severed from authority because the run was prohibited, the required result failed, or both. Every integration job was skipped.

| Runs | Runs | Runs | Runs |
| --- | --- | --- | --- |
| `30378350127@967ca856` | `30378913746@967ca856` | `30380426024@86034a4c` | `30381813021@34f1a0e6` |
| `30383223580@9f18c2ba` | `30384375468@0b20b416` | `30385629238@b87488ff` | `30386680346@94d0aa5f` |
| `30392620457@170adfac` | `30394625285@13fa4779` | `30396526485@dc1a5e11` | `30398136080@bdb26315` |
| `30399622200@2713f0c0` | `30401546077@98db47cd` | `30402676785@a7f05891` | `30405385146@ea231760` |
| `30406533825@748a964d` | `30407779002@4dda0b60` | `30408538201@de93588f` | `30409239748@44d0abfa` |
| `30409887948@955a4434` | `30410606157@bcfdbcf0` | `30411271884@a8c01fbc` | `30411888201@ca9fc44b` |
| `30412593189@e5065aed` | `30413260337@59f2258b` | `30413922375@76053908` | `30414533876@a31da784` |
| `30415183830@6694e4a7` | `30415740838@10659d14` | `30416278582@c8f284f4` | `30416903670@a3d84ec1` |
| `30417510224@db0157f0` | `30418092533@11027de3` | `30418786066@9f691ff8` | `30419430115@73563f37` |
| `30420098111@f49f89c4` | `30420694391@43d5e14f` | `30421378659@0d27d6cd` | `30422060236@7f0f2a57` |
| `30422705874@c253b876` | `30423281225@26cf7c48` | `30423882159@4f85353f` | `30424537139@afbb3d31` |
| `30425175531@41dfacd3` | `30425819925@3c10543b` | `30426516819@c8594dae` | `30427286738@44e3f8b0` |
| `30428012940@cd1c5d11` | `30428804694@5c2295b8` | `30429119599@5c2295b8` | `30429782506@84b3acbc` |
| `30430763715@0d0522ee` | `30431675509@cc717944` |  |  |

This prohibited-dispatch ledger is closed through run `30431675509`. A historical report artifact may be retained as a diagnostic record, but its internal `authority` spelling is ineffective and superseded by this disposition. No cross-run quorum exists: A from one run, B from another, or any other combination is forbidden.

#### 1.3 Later PR 319 CI and Quality/OpenTofu truth

PR 319 run `30461497437`, attempt 1, at exact head `6241fd1e6739560055ce952a25f033c64ad11ccc` occurred after the prohibited-dispatch boundary. It was a `pull_request` run and was cancelled. Native dispatch eligibility was skipped, and no Native C1, A–E, or integration job executed. Its partial ordinary CI results are non-authoritative history only.

The historical Quality path, including runs listed above where Quality reached the AWS-feasibility step, may have installed OpenTofu and downloaded provider plugins before running non-deploying initialization and validation. Neither a successful `init`/`validate` nor a cached/downloaded provider is AWS reachability, deployment, qualification, or evidence. This explicit disposition replaces any statement that no OpenTofu/provider activity occurred. Future CI must satisfy section 3's static-only replacement before any diagnostic is eligible.

### 2. Accept and exactly constrain the measured capability envelope

The exact measured sudo/prlimit/setpriv envelope in Context is **accepted**, narrowly, for Job B and thin integration diagnostics. The accepted spelling omits unsupported `--keep-caps`. It must use absolute executables, noninteractive sudo, default close-from-3 behavior, fixed `RLIMIT_NOFILE` `65536:65536`, authenticated runner identity, an empty reconstructed environment, fixed admitted Python, and the fixed job selector.

Immediately after setpriv enters tracked code and before the first source, process, namespace, mount, root, memfd, report, or other authority-bearing effect, the fixed bootstrap must read and strictly parse its own `/proc/self/status` and require this exact pre-effect state:

```text
real/effective/saved/fs UID = authenticated runner UID != 0
real/effective/saved/fs GID = authenticated runner GID != 0
Groups                         = empty
CapInh                         = 0000000000200000
CapPrm                         = 0000000000200000
CapEff                         = 0000000000200000
CapAmb                         = 0000000000200000
CapBnd                         = EXPECTED_T1_CAP_BND
```

`0000000000200000` is exactly capability bit 21, `CAP_SYS_ADMIN`, and no other bit. `EXPECTED_T1_CAP_BND` is one exact 16-character lowercase hexadecimal mask fixed as a source constant in the externally reviewed exact head; it is not an input, environment value, runtime fallback, or prefix/subset test. The observed `CapBnd` must equal that constant byte-for-byte, must contain `CAP_SYS_ADMIN`, and must contain no bit absent from the reviewed baseline. Any extra or missing bit, malformed status row, nonempty group, root identity, identity drift, or inability to observe the complete vector fails before effects and consumes the diagnostic if dispatched.

This is T1 diagnostic authority, not T2 workload or evidence authority. Before any untrusted input release, production must independently observe `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, and `CapAmb` all exactly `0000000000000000`, supplementary groups empty, locked `noroot`, `no_new_privs`, and the exact seccomp policy. The wrapper may not grant root UID, another effective/permitted/inheritable/ambient capability, a host namespace descriptor, a caller-selected path/argument/environment, or a fallback.

The wrapper is rejected for A, C, and D. Job E retains only its separately fixed root-authority provisioning route. Thin integration composes Job B's production closure, namespace, mount, and launcher transaction, so its diagnostic must use the byte-for-byte same envelope, changing only fixed admitted job identity values. Running integration unprivileged or with a broader envelope is rejected.

### 3. Source/static correction gate before any diagnostic

This ADR authorizes source/static correction and at most the two diagnostics in section 6. It grants no final-evidence run. No native selector, sudo, capability-bearing process, real namespace/mount/seccomp/`map_files` operation, OpenTofu, provider, AWS operation, deployment, or cloud operation may be used while making or reviewing corrections.

Ordinary `pull_request` and `push` Images security CI remains explicitly permitted under its existing workflow: it may build the local test images, pull pinned public images, scan them, generate SBOMs, and upload those security artifacts. That path is non-native and non-authoritative; it grants no deployment, production, campaign, cloud, diagnostic, or final-evidence authority. It is disjoint from workflow-dispatch diagnostics, for which the complete Images/Docker path remains mandatorily skipped.

Permitted correction is limited to existing surfaces and must:

1. correct the latest bounded Job B `runtime-launcher-exception-File` source defect without adding a fallback or weakening source admission;
2. wire integration through section 2's exact Job B capability envelope and enforce the exact pre-effect and sandbox capability vectors;
3. remove every OpenTofu/Terraform executable, installer, `init`, `validate`, provider-plugin download/load, AWS CLI/SDK/API, credential, and live-provider route from the Quality job for **every** CI event;
4. replace Quality's invocation of `deploy/aws-feasibility/validate.sh` with the tracked `npm run feasibility-source:check` static-only source checker for ordinary PR/push CI; that checker invokes no OpenTofu/Terraform/provider/AWS binary, install script, network acquisition, provider schema, backend, state, plan, refresh, or credentials; `validate.sh` may remain a manually gated non-CI helper but is unreachable from every workflow and grants no authority;
5. make every `workflow_dispatch` event in the corrected workflow skip the entire Images job, every Docker build/pull/scan/SBOM path, Native C1, and every OpenTofu/provider/AWS step; Native C1's skipped state is intentional and supplies no diagnostic or final evidence; a later ADR must explicitly amend this rule before a different dispatch shape;
6. define the complete workflow-dispatch input set as exactly `reviewed_sha`, `diagnostic_ordinal`, and `predecessor_run_id`; require ordinal exactly `1` or `2` and predecessor a canonical positive decimal run ID;
7. require exact source equality `reviewed_sha == github.sha == github.workflow_sha == checkout HEAD` on protected `refs/heads/main`, with the workflow ref bound to that same main SHA and no merge-ref substitution;
8. add section 5's pre-effect, metadata-only `actions:read` ledger gate and globally serialized non-cancelling diagnostic concurrency;
9. make every diagnostic in-memory report, uploaded artifact, artifact name, operation receipt, and cleanup authority state `authority="none"`; the string `exact-run-native-qualification` is unreachable from every diagnostic selector;
10. add exact capability, process, descriptor, namespace, mount, path, limit, checkout, report, and Job E root-authority cleanup observations for B, E, and integration;
11. run two independent trusted closure preparations in integration as section 4 requires and bind only their diagnostic comparison into the closed authority-none report;
12. make report cleanup classify “no publication occurred” without claiming publication success, while preserving native failure;
13. remove every integration download of, trust in, or cross-check against A–E artifacts; remove `actions/download-artifact`, downloaded-report comparison, and broad `rm -rf` cleanup from the diagnostic workflow; and
14. update only existing portable/static tests, schema goldens, workflow parsing, and line gates needed to causally prove these rules.

Diagnostic integration composes production owners but consumes no A–E artifact and inherits no A–E result as evidence. Cross-report artifact verification is deferred to an external verifier whose exact bytes and rules must be named by a later final-run ADR.

No new dependency, service, native job, retry path, generated security program, report authority, or native scenario is permitted. The OpenTofu static replacement remains a source/static correction even though it applies to ordinary PR CI. Diagnostic-derived correction after diagnostic 1 is limited to one measured root cause, requires a new exact main SHA and external review, and cannot restore forbidden execution.

The only revised individual gross-addition highs are:

| Existing surface | ADR 0093 high | ADR 0094 high |
| --- | ---: | ---: |
| `.github/workflows/ci.yml` Outcome Two addition | 400 | **560** |
| `package.json` feasibility static-check registration | unlisted | **5** |
| `scripts/check-feasibility-source.ts` | unlisted | **140** |
| `test/ci-infrastructure-boundary.test.ts` | unlisted | **120** |
| `scripts/native-qualification/common.py` | 1,900 | **2,150** |
| `schemas/native-qualification-report-v1alpha1.json` | 700 | **860** |
| `scripts/validate-schemas.ts` Outcome Two addition | 300 | **340** |
| `test/outcome-two-recovery-portable.py` | 1,500 | **1,650** |
| `test/outcome-two-trusted-launcher-portable.py` | 2,300 | **2,550** |

Every other ADR 0093 individual high remains unchanged. The three infrastructure-static surfaces are included in trusted/portable accounting and authorize no execution or change to deployment helpers. The binding trusted/portable subtotal remains 19,000, native subtotal remains 10,000, and listed aggregate remains 29,000 gross physical additions from `bec0a19b0b984f88ab9c2effc5059f3737915caa`. Deletion, movement, generated data, packed control flow, or unused allowance supplies no credit. Stop for another ADR before crossing any individual or binding aggregate high or changing the accepted envelope.

### 4. Two trusted closure preparations

Every diagnostic integration transaction performs exactly two fresh trusted closure preparations, sequentially on the same fresh runner and exact source:

1. preparation 1 authenticates the complete fixed Python/gzip/zstd/loader/library closure, obtains a canonical closure report, settles no executable handoff, closes every descriptor/helper/private path, and proves its complete preparation baseline restored;
2. only after that restoration, preparation 2 independently repeats resolution, authentication, mapping validation, sealing, canonical encoding, and preparation cleanup;
3. the two canonical closure reports must be byte-identical, including the single terminal LF; and
4. only preparation 2 may issue the one-shot handoff consumed by thin integration.

The two preparations may share fixed source policy but no mutable owner, helper, descriptor, memfd, report object, cache, namespace, mount, private root, or cleanup claim. A mismatch, unavailable primitive, first-preparation residue, close uncertainty, or inability to compare is terminal. It may not trigger a third preparation.

The integration result and closed diagnostic report record only fixed categorical success, preparation count `2`, and the canonical report SHA-256/size already permitted by the metadata disclosure boundary. The report and its artifact always carry `authority="none"`. They do not disclose report bytes, paths, generations, PIDs, descriptors, mappings, addresses, or host identities.

### 5. Mechanically serialized ledger gate and fixed deadlines

Workflow-dispatch diagnostics use one repository-global concurrency group, literal `outcome-two-native-diagnostic-v1`, with `cancel-in-progress: false`. The complete diagnostic workflow, not merely eligibility, holds that group until terminal completion. Ordinary PR/push CI uses a disjoint group. This prevents cancellation of a running diagnostic and prevents running overlap, but GitHub may replace or cancel an older **pending** run when a newer run enters the same concurrency group. Therefore every created run immediately consumes its claimed ordinal even if it remains pending, is replaced, or is cancelled. The metadata ledger must classify every such run; a newer run that observes a cancelled/pending predecessor, duplicate ordinal, or replacement attempt rejects before checkout or any repository/native effect. No queued replacement can recover an ordinal or gain authority.

Before checkout, Quality, sudo, or any repository executable, the eligibility job has exactly `actions: read` with every other repository permission set to none and performs one fixed metadata ledger read. This ADR explicitly authorizes an ephemeral GitHub Actions token only for bounded pagination of CI workflow-run metadata and bounded job-conclusion reads for named predecessor diagnostics. The token is never printed, persisted, forwarded, or supplied to checked-out/native code. No log, artifact, source, issue, comment, release, environment, secret, AWS, provider, or other API read/write is authorized.

The fixed gate must:

1. require current event `workflow_dispatch`, attempt 1, protected main, authorized actor/sender, exact canonical inputs, and the SHA equality in section 3;
2. enumerate every prior CI `workflow_dispatch` run after boundary run `30431675509`, excluding only the current run, until that boundary is found exactly once; reject truncation, pagination uncertainty, API error, unknown event shape, or a run it cannot classify;
3. identify ADR 0094 diagnostics through one canonical workflow run-name binding ordinal, predecessor run ID, and exact reviewed SHA; no caller text outside the three closed inputs enters that name;
4. reject any malformed post-boundary dispatch, duplicate ordinal, duplicate run ID, same-SHA diagnostic, later attempt, rerun, cancelled/in-progress predecessor, missing required job, uncertain cleanup, or already-created ordinal 2;
5. for ordinal 1, require `predecessor_run_id == 30431675509` and no prior ADR 0094 diagnostic;
6. for ordinal 2, require exactly one completed ordinal-1 diagnostic, `predecessor_run_id` equal to its exact run ID, a different exact main SHA, a failed required diagnostic result with every cleanup/root-removal conclusion terminally known, and no prior ordinal-2 run; and
7. reject ordinal 2 if ordinal 1 was all green, cancelled, skipped, timed out, incomplete, cleanup-uncertain, or otherwise not one completed correctable failure.

A rejected or malformed dispatch performs no checkout, Quality, native, image, OpenTofu, provider, AWS, or repository-code effect. A created ordinal consumes its slot; no API error or transient replenishes it.

Deadlines are exact and may only shorten on failure:

- every A–E and integration diagnostic job: GitHub job timeout exactly 10 minutes;
- tracked outer operation watchdog: 360 seconds from immediately before first effect through native-operation settlement;
- on watchdog expiry: close release/input gates immediately, TERM exact owned identities, wait 5 seconds, KILL only revalidated survivors, then reap for at most 5 seconds;
- native/root/report/path cleanup: one 90-second monotonic aggregate deadline after operation termination, with each workflow cleanup step capped at 2 minutes; and
- eligibility and required-result jobs: 2 minutes each.

Timeout, deadline expiry, inability to start the watchdog before effects, identity uncertainty, or cleanup overrun is failure and cannot be retried or converted to absence.

### 6. At most two authority-none diagnostic runs

The smallest defensible allowance is **at most two diagnostics**. The first corrected diagnostic is the first exposure of both corrected Job B and integration under their common measured envelope. The second permits at most one measured correction after one complete, cleanup-certain failure. A larger allowance would recreate the prohibited campaign.

Each diagnostic must satisfy sections 2–5, use its mechanically admitted ordinal, and bind one externally reviewed exact main SHA and exact workflow/source/schema/test blobs. There is no rerun, retry, replacement attempt, duplicate dispatch, concurrent run, or same-SHA second diagnostic. Failure consumes the ordinal. After the first all-green diagnostic, ordinal 2 expires.

Diagnostic 1 may lead to diagnostic 2 only for one measured source defect within section 3. If diagnostic 2 fails, or a different architecture/surface is required, execution stops for a new ADR. Environment/transient classification does not replenish an ordinal.

Every diagnostic report and artifact has authority exactly `none`, including all-green A–E and integration reports. Job success cannot be separated, combined across runs, or promoted. No diagnostic can close Outcome 2 or authorize final evidence.

### 7. Ten reviews and final execution are deferred

ADR 0094 authorizes no final-evidence workflow input, environment, job, report authority, artifact authority, verifier, or run. It does not require or approve a protected final environment because final execution is entirely deferred.

An all-green diagnostic makes one exact head eligible for fresh review only. Ten fresh exact-head review reports must retain ADR 0093's dimensions: authentication/source admission, common/report/schema, workflow/ledger, A/B, C, D, E, integration, portable/static causality, and holistic authority/cleanup. Reviewers classify P0–P3, but only Nick Byrne may freeze the final P0/P1 blocker decision. False-success, substituted-authority, suppressed-failure, foreign cleanup/signaling, residue, or cleanup-uncertainty findings must be P0/P1 and cannot be deferred as P2/P3.

A later separately accepted final-run ADR is mandatory. It must name, in its accepted text:

- the exact 40-character main SHA proposed for final execution;
- the exact workflow Git blob/object identity and SHA-256;
- every exact parser, closure, launcher, common, A–E, integration, schema, and external-verifier source blob/object identity and SHA-256 used by the final transaction;
- the one all-green diagnostic run ID and attempt 1 for that same unchanged SHA;
- all ten exact review report paths, report digests, reviewed SHA, and dispositions;
- Nick Byrne's exact user-frozen P0/P1 decision and every resolved blocker;
- the external cross-report verifier, artifact inputs, authority transition, final cleanup, exact run count, attempt rule, and stop conditions; and
- the continuing AWS/provider/OpenTofu/SSM/deployment/campaign boundary.

Until that ADR is accepted, every report/artifact remains authority `none`; no exact-run authority string, final dispatch, artifact promotion, external verification claim, issue closure, or production inference is permitted.

### 8. Authenticated cleanup, zero residue, and root-authority removal

A diagnostic pass report or all-green diagnostic is impossible until all applicable cleanup is observed after the last effect.

For B and integration, the surviving unprivileged owner must prove the capability-bearing process and all owned descendants are reaped, every pidfd/descriptor/gate is closed, every private root/path is removed by retained parent authority, every mount and namespace handle is gone, limits are restored, checkout bytes/config are unchanged, all owner registries are empty, and no process retaining `CAP_SYS_ADMIN` remains. Runner disposal is not evidence.

For E, root provisioning is a write-ahead transaction. Cleanup must authenticate the exact reviewed source, bootstrap, authority and state generations; remove only those exact owned files; fsync affected directories; remove only exact empty directories created by the transaction; and reobserve absence. Root cleanup runs under `always()` and has a named output required by the diagnostic result. Provision failure does not permit pathname-only deletion. Mismatch or foreign state is preserved and fails.

For every report, the retained custodian authenticates exact report bytes, generation, run, attempt, head, job, authority-none classification, and upload acknowledgement before quarantine/unlink. Diagnostic integration performs no artifact download, so no downloaded report path or broad downloaded-tree cleanup may exist. Cleanup failure never turns a failed publication into success and never deletes a foreign replacement.

“Zero residue” covers local descriptors, processes/descendants, capabilities, files/private roots, mounts, namespace handles, limits, checkout mutation, root-authority files/directories, and report staging/publication paths. Intentionally retained GitHub diagnostic artifacts are external authority-none observations, not runner residue. They cannot inherit authority under this ADR.

### 9. Absolute future non-AWS boundary

Historical Quality OpenTofu/provider activity is truthfully recorded in Context and section 1.3; it grants no authority and is not ratified. For every correction and diagnostic authorized by this ADR, AWS/provider/OpenTofu/SSM/deployment/campaign activity is absolutely forbidden:

- no AWS API, CLI, console, credential, account, role, STS, EC2, S3, IAM, KMS, SDK, or other AWS use;
- no SSM or remote-command/session route;
- no OpenTofu/Terraform install or execution, provider initialization/download/load/validation, backend, plan, apply, import, refresh, destroy, or state access;
- no deployment, release, production, campaign, Phase B, Stage 2 campaign, workload campaign, KVM, Kata, containerd, Docker, image job, or cloud qualification in a workflow-dispatch diagnostic; and
- no inference of authority from source review, static checks, metadata reads, diagnostic green, or authority-none artifacts.

No prohibited credential or secret may enter a diagnostic. The one GitHub Actions metadata read in section 5 is the sole network/API exception and grants no source, artifact, provider, or cloud authority. If the selected dispatch path can invoke Images/Docker, Native C1, OpenTofu, a provider, AWS, or another prohibited operation, eligibility must fail before checkout and no diagnostic is authorized.

## Integration order and stop conditions

1. Merge this documentation decision without dispatching anything.
2. Implement only section 3 source/static corrections, including static-only Quality for every event and diagnostic skips for Images/Docker and Native C1.
3. Run only permitted non-native portable/static, schema, workflow-parser, ledger-model, line-accounting, `git diff --check`, and repository-integrity gates.
4. Prove statically that no CI Quality event can invoke OpenTofu/provider/AWS and no workflow dispatch can invoke Images/Docker or Native C1.
5. Obtain external review of the exact main SHA, workflow, capability baseline, and changed source/schema/test blobs.
6. Optionally consume mechanically admitted diagnostic ordinal 1; stop on green, otherwise make only one measured correction.
7. If section 5 permits it, externally review a different exact main SHA and optionally consume ordinal 2; stop regardless of outcome.
8. After one all-green diagnostic, freeze that exact head, obtain the ten reports and user decision in section 7, and prepare a later final-run ADR.
9. Do not execute final evidence, external cross-report authority verification, issue closure, deployment, or cloud activity under ADR 0094.
10. Do not merge, dispatch, rerun, push, or execute anything under this documentation amendment itself.

## Consequences

Historical partial successes and OpenTofu/provider downloads remain truthful observations but lose every path to authority. The measured Job B capability wrapper is accepted only with exact pre-effect vectors and complete sandbox drop. Integration is symmetric, artifact-independent, and diagnostic-only. Two independent closure preparations challenge determinism and cleanup without creating evidence authority.

At most two globally serialized, mechanically budgeted, attempt-1 diagnostics replace the prior open-ended campaign. Every report and artifact remains authority `none`. Final evidence, external cross-report verification, and any authority transition require a later accepted exact-head ADR naming the green diagnostic, exact blobs, ten reviews, and Nick Byrne's frozen P0/P1 decision.
