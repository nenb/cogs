# ADR 0094: Bound native diagnostic and final-evidence authority

- **Status:** Accepted
- **Decision date:** 2026-07-29
- **Decision owner:** Nick Byrne
- **Accepted by:** Nick Byrne's explicit instruction to prepare this bounded non-AWS execution decision.
- **Architecture predecessors:** ADR 0093 and, where non-conflicting, ADRs 0087–0092.
- **Current exact implementation head observed:** `cc7179449dd5d0fa222fbb141b234bf48ac6da75`.
- **Last historical run in scope:** GitHub Actions run `30431675509`, attempt 1.
- **Accounting predecessor:** `bec0a19b0b984f88ab9c2effc5059f3737915caa`.

## Context

ADR 0093 authorized source and portable/static correction only. It explicitly prohibited native execution, sudo, workflow dispatch/rerun, and integration execution. Native dispatches nevertheless followed the merge of the ADR 0093 implementation. None reached the required all-green result. Integration never ran because Job B never passed.

The latest attempt, run `30431675509` at exact main head `cc7179449dd5d0fa222fbb141b234bf48ac6da75`, passed Quality, C1, A, C, D, and E. Job B failed in the admitted launcher with the bounded diagnostic `runtime-launcher-exception-File`; report upload did not occur, report cleanup failed because no publication existed, integration was skipped, and the required result failed.

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

A bounded architecture is now required to stop the unreviewed correction/dispatch loop, admit only the minimum remaining diagnostic opportunity, and separate diagnostic green from final evidence authority.

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

This ledger is closed through run `30431675509`. A historical report artifact may be retained as a diagnostic record, but its internal `authority` spelling is ineffective and superseded by this disposition. No cross-run quorum exists: A from one run, B from another, or any other combination is forbidden.

### 2. Accept the measured Job B capability envelope

The exact measured sudo/prlimit/setpriv envelope in Context is **accepted**, narrowly, for Job B. The accepted spelling omits unsupported `--keep-caps`. It must use absolute executables, noninteractive sudo, default close-from-3 behavior, fixed `RLIMIT_NOFILE` `65536:65536`, authenticated runner UID/GID, empty supplementary groups, only inheritable and ambient `CAP_SYS_ADMIN`, an empty reconstructed environment, fixed admitted Python, and the fixed Job B selector.

This is T1 qualification authority, not T2 workload authority. Before input release, production must observe all five T2 capability sets as zero, locked `noroot`, `no_new_privs`, and the exact seccomp policy. The wrapper may not grant root UID, another capability, a host namespace descriptor, a caller-selected path/argument/environment, or a fallback. Failure to create the intended namespace/mount transaction is a failed observation, never an environment skip.

The wrapper is rejected for A, C, and D. Job E retains only its separately fixed root-authority provisioning route.

Thin integration composes the same production closure, namespace, mount, and launcher transaction as Job B. The architecture therefore **requires integration to use the byte-for-byte same measured sudo/prlimit/setpriv capability envelope**, changing only the fixed admitted driver/job identity and corresponding allowlisted environment values. Running integration unprivileged, as the current workflow does, is rejected. A broader integration privilege envelope is also rejected.

### 3. Source and static corrections before any execution

Only measured source/static correction is authorized before the first new diagnostic run. No native selector or real privileged primitive may be used while making or reviewing these corrections.

Permitted correction is limited to existing ADR 0093 surfaces and must:

1. correct the latest bounded Job B `runtime-launcher-exception-File` source defect without adding a fallback or weakening source admission;
2. wire integration through the exact accepted Job B capability envelope;
3. require `reviewed_sha == github.sha == github.workflow_sha` at the protected main envelope and add one closed dispatch input, `execution_kind`, whose only values are `diagnostic` and `final`;
4. bind `execution_kind` through context, immutable operation receipt, report schema, artifact name, cleanup authority, and final gate; diagnostic reports use authority `none`, while only a complete `final` run may use `exact-run-native-qualification`;
5. add an exact observed capability-envelope check and post-transaction capability/process/namespace/mount/path cleanup checks for B and integration;
6. run two independent trusted closure preparations in integration as section 4 requires and bind the comparison into the closed production result and native report schema;
7. make report cleanup idempotently classify “no publication occurred” without claiming successful publication, while preserving failure of the native transaction;
8. bind Job E root-authority removal to an explicit required workflow result;
9. replace unauthenticated or broad cleanup, including integration's downloaded-tree `rm -rf`, with exact retained parent/object authority and bounded reverse cleanup; and
10. update only the existing portable/static tests, schema goldens, workflow parser, and line gates needed to make these changes causal.

No new implementation file, action, dependency, service, job, selector other than the closed `execution_kind` input, retry path, generated security program, report disclosure beyond fixed `execution_kind` and section 4 preparation metadata, or native scenario is permitted. Diagnostic-derived source changes after a failed authorized attempt are limited to one measured root cause from that attempt and require a new exact main SHA and new external review.

The only revised individual gross-addition highs are:

| Existing surface | ADR 0093 high | ADR 0094 high |
| --- | ---: | ---: |
| `.github/workflows/ci.yml` Outcome Two addition | 400 | **480** |
| `scripts/native-qualification/common.py` | 1,900 | **2,150** |
| `schemas/native-qualification-report-v1alpha1.json` | 700 | **860** |
| `scripts/validate-schemas.ts` Outcome Two addition | 300 | **340** |
| `test/outcome-two-recovery-portable.py` | 1,500 | **1,650** |
| `test/outcome-two-trusted-launcher-portable.py` | 2,300 | **2,550** |

Every other ADR 0093 individual high remains unchanged. The binding trusted/portable subtotal remains 19,000, native subtotal remains 10,000, and listed aggregate remains 29,000 gross physical additions from `bec0a19b0b984f88ab9c2effc5059f3737915caa`. Deletion, movement, generated data, packed control flow, or unused allowance supplies no credit. Stop for another ADR before crossing any individual or binding aggregate high or changing the accepted envelope.

### 4. Two trusted closure preparations

Every integration transaction, diagnostic or final, performs exactly two fresh trusted closure preparations, sequentially on the same fresh runner and exact source:

1. preparation 1 authenticates the complete fixed Python/gzip/zstd/loader/library closure, obtains a canonical closure report, settles no executable handoff, closes every descriptor/helper/private path, and proves its complete preparation baseline restored;
2. only after that restoration, preparation 2 independently repeats resolution, authentication, mapping validation, sealing, canonical encoding, and preparation cleanup;
3. the two canonical closure reports must be byte-identical, including the single terminal LF; and
4. only preparation 2 may issue the one-shot handoff consumed by thin integration.

The two preparations may share fixed source policy but no mutable owner, helper, descriptor, memfd, report object, cache, namespace, mount, private root, or cleanup claim. A mismatch, unavailable primitive, first-preparation residue, close uncertainty, or inability to compare is terminal. It may not trigger a third preparation.

The integration result and closed native report record only fixed categorical success, preparation count `2`, and the canonical report SHA-256/size already permitted by the metadata disclosure boundary. They do not disclose report bytes, paths, generations, PIDs, descriptors, mappings, addresses, or host identities.

### 5. Exactly two possible diagnostic runs

The smallest defensible diagnostic allowance is **at most two runs**. One run is not defensible because no historical integration job executed; the first corrected run is the first exposure of both corrected Job B and integration under their common measured envelope. Two runs permit at most one measured source correction after that first exposure. A larger allowance would recreate the prohibited correction/dispatch campaign.

Each diagnostic run must satisfy all of these conditions:

- event is `workflow_dispatch` with `execution_kind=diagnostic` on the protected default branch `main`;
- the workflow envelope SHA, `github.sha`, and checked-out source are one externally reviewed exact main commit;
- `reviewed_sha` is that same exact 40-character main SHA, not another commit or merge ref;
- run attempt is exactly 1;
- the authorized actor, triggering actor, sender, and externally recorded reviewer approval agree;
- the exact workflow and every changed source/schema/test blob were reviewed before dispatch;
- there is no rerun, retry, replacement attempt, duplicate dispatch, concurrent run, or same-SHA second diagnostic;
- failure, cancellation, timeout, skip, cleanup uncertainty, root-authority-removal uncertainty, or missing report consumes that diagnostic allowance; and
- after the first all-green diagnostic, the unused second allowance expires.

If diagnostic 1 fails, only the one measured source/static correction in section 3 may lead to diagnostic 2. If diagnostic 2 fails, or if a different defect or architecture change is required, execution stops for a new ADR. Environment/transient classification does not replenish an attempt.

Both diagnostics have authority `none`. Their artifacts and job successes remain non-authoritative observations even if the complete workflow is green. They cannot close Outcome 2 or supply final evidence.

### 6. Review gate is user-frozen P0/P1 only

This section narrowly supersedes ADR 0093's requirement that ten reviews have no unresolved P0–P3 finding.

After the first all-green diagnostic, freeze one exact main head with no source change. Fresh exact-head reviews retain ADR 0093's ten review dimensions. Reviewers classify findings as P0–P3, but only Nick Byrne may freeze the final P0/P1 blocker set and authorize the final evidence run.

- Every user-frozen P0 and P1 blocker must be resolved and freshly reviewed before final execution.
- P2 and P3 findings are recorded as bounded follow-ups and do not by severity alone block final evidence.
- A finding that can enable false success, admit substituted authority, suppress a required failure, delete or signal a foreign object, leave root/capability/process/descriptor/path/mount/namespace residue, or make cleanup absence uncertain **must be P0 or P1**. It cannot be downgraded, waived, or deferred as P2/P3.
- A P2/P3 follow-up may not change workflow gating, result derivation, trust admission, the capability envelope, report authority, cleanup ownership, or final evidence interpretation. Such a change requires reclassification and a new exact review head.
- Automated severity, reviewer disagreement, or an agent-authored “resolved” label cannot alter the user-frozen set.

The all-green diagnostic is only eligibility for these fresh reviews. Reviews performed before it do not grant final evidence authority.

### 7. One final evidence run

After section 6 is satisfied, exactly one final evidence run may be authorized for the same byte-for-byte exact head that produced the all-green diagnostic. No commit, merge, formatting change, review record committed into the tree, workflow edit, or dependency change may intervene.

The final run has `execution_kind=final` and the same protected-main, exact-head, attempt-1, actor, no-rerun, no-retry, and no-concurrency rules as a diagnostic. Diagnostic artifacts or an omitted/wrong execution kind cannot satisfy its gate. It must be all green in one run:

- eligibility and Quality;
- A, B, C, D, and E;
- Job E authenticated root-authority removal;
- integration with two byte-identical trusted closure preparations;
- all six exact report uploads and authenticated local report cleanup;
- integration uploaded-byte comparison and exact download cleanup; and
- the required final result.

Only this one complete final run may have `exact-run-native-qualification` evidence authority, and only for its exact head, workflow/source blobs, run ID, attempt 1, fixed checks, reports, and reviewed applicability. Individual job success is not separable authority. A failed/cancelled/skipped final run grants no authority and has no rerun or replacement under this ADR; stop for a new ADR.

### 8. Authenticated cleanup, zero residue, and root-authority removal

A pass report, diagnostic green, or final green is impossible until all applicable cleanup is observed after the last effect.

For B and integration, the surviving unprivileged owner must prove the capability-bearing process and all owned descendants are reaped, every pidfd/descriptor/gate is closed, every private root/path is removed by retained parent authority, every mount and namespace handle is gone, limits are restored, checkout bytes/config are unchanged, all owner registries are empty, and no process retaining `CAP_SYS_ADMIN` remains. Runner disposal is not evidence.

For E, root provisioning is a write-ahead transaction. Cleanup must authenticate the exact reviewed source, bootstrap, authority and state generations; remove only those exact owned files; fsync affected directories; remove only exact empty directories created by the transaction; and reobserve absence. Root cleanup runs under `always()` and has a named output required by the final result. Provision failure does not permit pathname-only deletion. Mismatch or foreign state is preserved and fails.

For every report, the retained custodian authenticates exact report bytes, generation, run, attempt, head, job, and upload acknowledgement before quarantine/unlink. For integration download cleanup, retained directory and file identities replace `rm -rf`; exactly one `report.json` generation is removed and parent absence is reread. Cleanup failure never turns a failed publication into success and never deletes a foreign replacement.

“Zero residue” covers local descriptors, processes/descendants, capabilities, files/private roots, mounts, namespace handles, limits, checkout mutation, root-authority files/directories, report staging/publication paths, and downloaded report paths. Intentionally retained GitHub report artifacts are external evidence objects, not runner residue; diagnostic artifacts remain authority `none`, and final artifacts inherit authority only through the one final all-green run.

### 9. Absolute non-AWS boundary

This ADR authorizes no AWS action of any kind. It absolutely forbids:

- AWS API, CLI, console, credential, account, role, STS, EC2, S3, IAM, KMS, or other AWS use;
- SSM or any remote-command/session route;
- provider initialization, validation against a live provider, planning, applying, importing, refreshing, destroying, or state access;
- OpenTofu/Terraform execution;
- deployment, release, production, campaign, Phase B, Stage 2 campaign, workload campaign, KVM, Kata, containerd, Docker, or cloud qualification; and
- inferring any such authority from source review, static tests, a diagnostic green, or final native evidence.

No AWS/provider/OpenTofu/SSM/deployment/campaign credential or secret may enter a diagnostic or final job. Existing offline source/schema tests do not grant an exception to execute or contact any provider. If the selected workflow path would invoke one of the prohibited operations, the run is ineligible and must not be dispatched.

## Integration order and stop conditions

1. Merge this documentation decision without dispatching anything.
2. Implement only section 3 source/static corrections.
3. Run ordinary non-native portable/static, schema, workflow-parser, line-accounting, `git diff --check`, and repository-integrity gates.
4. Obtain external review of the exact main SHA and changed blobs.
5. Optionally consume diagnostic 1; stop on green, otherwise make only one measured correction.
6. If needed, externally review the new exact main SHA and optionally consume diagnostic 2; stop regardless of outcome.
7. After one diagnostic is all green, freeze that exact head and complete section 6 reviews.
8. Only after Nick Byrne freezes and clears P0/P1 blockers may one final evidence run occur.
9. Do not merge, dispatch, rerun, or execute anything under this documentation commit itself.

## Consequences

Historical partial successes remain useful observations but lose every path to authority. The exact measured Job B capability wrapper is accepted without broadening T2, and integration is made symmetric rather than relying on an unmeasured weaker envelope. Two independent closure preparations challenge canonical determinism and preparation cleanup before handoff.

At most two non-authoritative diagnostic runs and one separately reviewed final run replace the prior open-ended campaign. Final authority remains atomic: one exact head, one attempt, one all-green run, authenticated cleanup, zero local residue, and no AWS/provider/OpenTofu/SSM/deployment/campaign activity.
