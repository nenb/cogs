# ADR 0088: Correct capability implementation review findings

- Status: Accepted
- Date: 2026-07-27
- Decision owner: Nick Byrne
- Accepted by: Delegated project lead on 2026-07-27 under Nick Byrne's standing authorization to complete all non-AWS work.
- Exact reviewed implementation head: `9c86bc5add169fadd86574fd8468422a46ee3ed0`.
- Exact review-integration head: `f6df86433ffe510784e3b68ecb13593fa4a28e41`, the current integration head read from Git immediately before this decision. Its only changes after the reviewed implementation head are the five review reports named below; the five capability implementation surfaces are byte-identical at both heads.
- Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`, unchanged from ADR 0087.
- Amendment scope: This ADR amends only ADR 0087's capability implementation behavior, portable/static qualification requirements, implementation diff-format gate, and five capability numeric highs. Every non-conflicting ADR 0087 requirement remains binding, including the separate 7,000-line production/portable/native/integration high and every production, workflow-observation, AWS, cloud, provider, OpenTofu, deployment, and issue-closure stop.

## Context

ADR 0087 authorized implementation of a non-authoritative hosted-runner capability observation on exactly five surfaces, but authorized no observation attempt. Five independent reports then reviewed exact implementation head `9c86bc5add169fadd86574fd8468422a46ee3ed0`:

- `.pi/outcome-two/capability-review-workflow.md`;
- `.pi/outcome-two/capability-review-schema.md`;
- `.pi/outcome-two/capability-review-driver.md`;
- `.pi/outcome-two/capability-review-tests.md`; and
- `.pi/outcome-two/capability-review-holistic.md`.

The reports were integrated without implementation changes at exact head `f6df86433ffe510784e3b68ecb13593fa4a28e41`. All five verdicts block an observation. They found no P0, but found capability-only P1–P3 defects:

- numeric UID/GID map rows prohibited by ADR 0087 are emitted into the ordinary public log;
- the driver incorrectly requires `github.sha` to equal the event merge SHA even though source and envelope identities must remain separate;
- many fixed cases lack complete status/errno/prerequisite/postcondition coupling, allowing impossible complete reports and copying prerequisite failures onto operations that were not attempted;
- seccomp query failures become fabricated zero values, the child proc distinction is never measured, and driver/schema numeric domains differ;
- descriptor, child, limit, mount, namespace, name, and checkout cleanup claims begin optimistically rather than from captured and restored baselines;
- deadlines do not stop new effects, child identity is not retained through exact reap, parent death is not handled before release, and a worker crash or workflow timeout can strand a privileged or irreversible case;
- case children retain excess descriptors, environment, checkout working-directory access, and stdout/stderr routes; the root path component and temporary/mount cleanup authorities are not fully authenticated;
- the credential gate misses unscoped `http.extraheader` and push URLs;
- the portable tests do not drive production state/syscall/process adapters, do not independently mutate every semantic relationship, can miss an unnamed fourth workflow step, and omit optimized-mode regression coverage; and
- two non-transferable test-file highs are already crossed. The current 2,744-line implementation leaves too little driver and test room for readable lifecycle recovery and the required hostile matrices.

Two review reports also noted trailing whitespace in the historical implementation-gate report. That report is review input, not one of the five implementation surfaces. Rewriting it would alter retained review history and would not improve the capability implementation. This decision therefore scopes the implementation-accounting diff-format command to the exact five implementation surfaces while still requiring ordinary formatter and repository checks for every newly changed file.

A passing current self-test, schema check, formatter, typecheck, or happy-path fixture does not resolve these findings. No report from either exact head has authority, and no real capability observation has been approved or run.

## Decision

### 1. Exact correction scope

Correct the findings only on the five ADR 0087 capability surfaces:

```text
.github/workflows/outcome-two-runner-capability.yml
schemas/runner-capability-probe-v1alpha1.json
scripts/runner-capability-probe.py
test/runner-capability-probe.test.ts
test/outcome-two-runner-capability-workflow.test.ts
```

The report version remains `cogs.runner-capability-probe/v1alpha1`, `authority` remains exactly `none`, `qualified` remains exactly false, and output remains log-only. No sixth implementation surface, dependency, lockfile, generated executable, production import, production file, existing CI workflow, action, artifact, upload, cache, network acquisition, package installation, retry, fallback, or alternate executable is authorized.

The correction must be based on the reviewed bytes at `9c86bc5add169fadd86574fd8468422a46ee3ed0`, as integrated unchanged at `f6df86433ffe510784e3b68ecb13593fa4a28e41`. Review reports and this ADR are decision inputs, not implementation line-credit or executable surfaces.

### 2. UID/GID map redaction and source/envelope separation

Remove `uid_map`, `gid_map`, `idMap`, `nullableIdMap`, every numeric ID-map row, and every fixture or validator route that admits those values. The fixed helper may inspect procfs internally, but it must reduce the result before crossing its categorical result pipe. Neither helper records nor the public report may serialize an inside ID, outside ID, row count value, numeric triple, UID, or GID.

`namespaces.user_direct_root` may retain only these closed categorical facts:

- the user-namespace creation status;
- a UID-map observation status and a nullable boolean saying whether the fixed expected single-root mapping was observed;
- a GID-map observation status and the corresponding nullable boolean;
- the closed `setgroups` category; and
- the fixed prerequisite identifier required by section 3 when an operation was not attempted.

An `ok` map-observation status requires its categorical boolean to be true. A successful read with the wrong shape is `mismatch` with false. A map not read has a null boolean and a correctly coupled non-`ok` status. Tests must reject the old keys, numeric triples at any depth, ID-shaped helper output, and UID/GID canary values in canonical bytes, stdout, and stderr.

Keep source and envelope identities structurally and semantically separate:

- same-repository head repository equals the fixed repository;
- checkout SHA equals PR head SHA;
- each of base SHA, `github.sha`, `github.workflow_sha`, event merge SHA, and PR head SHA is validated only against its own closed field contract; and
- no equality or inequality among those five values is required or inferred.

The driver and both test suites must remove `github_sha == event_merge_sha`. The golden report must use distinct valid values for PR head, base, `github.sha`, `github.workflow_sha`, and event merge SHA so that a future equality assumption fails tests. A source-head workflow blob digest remains only `source_head_workflow_blob_sha256`; it is never called the executed-workflow digest.

Use the same numeric domains everywhere: `run_id` is a nonzero decimal string of 1–20 digits, `run_attempt` is exactly integer 1, and `pull_request_number` is an integer from 1 through 2,147,483,647. Driver parsing, schema, canonical fixtures, and boundary mutations must agree exactly.

### 3. Complete semantic coupling

The schema remains recursively closed, but schema shape alone is insufficient. The production validator and a genuinely independent TypeScript validator must each enforce every fixed relationship below.

Every `ProbeStatus` carries exactly state, errno, and a nullable closed prerequisite check ID. The prerequisite ID is selected from fixed report check IDs; it is never a free-form diagnostic.

- `ok`: errno and prerequisite are null; the operation was attempted and every required postcondition is present and true.
- `unsupported`: prerequisite is null; errno is null only for a proved absent fixed object, otherwise errno is only `ENOSYS` or `EOPNOTSUPP`; unobserved postconditions are null.
- `denied`: prerequisite is null, errno is only `EPERM` or `EACCES`, and unobserved postconditions are null.
- `blocked`: errno is null, prerequisite names one fixed non-`ok` prerequisite, the operation was not attempted, and every postcondition is null.
- `mismatch`: errno and prerequisite are null, the operation or syscall succeeded, and at least one exact required postcondition is present and false.
- `error`: prerequisite is null, errno is another allowlisted integer from 1 through 4,095, and unobserved postconditions are null.

An upstream failure is never copied into a downstream operation. In particular, namespace creation/propagation, child filter setup, fixed-tool identity, sudo admission, proc mount, NNP, KVM open, tmpfile open, and O_PATH open remain their own results. Each unattempted dependent operation is `blocked` and names the failed fixed prerequisite.

The relationship matrix must cover, without omission:

- runner image and kernel queries;
- every fixed tool and sudo identity, including absent-object semantics and all metadata nullability;
- sudo noninteractive and both close-from cases, including exact fd postconditions and exit-code categories;
- low/high `close_range`, exec/CLOEXEC, hard-limit prerequisite, limit restoration, and inherited baseline restoration;
- runner-temp/private-tmpfs open, link, identity, mode, ownership, and cleanup;
- same/across-mount O_PATH open, namespace/propagation prerequisite, stability, bind identity, and cleanup;
- network, mount, PID, direct-user, and combined user/mount/PID namespace creation and their distinct/PID-1/map/proc/cleanup postconditions;
- all six proc/map cases, capability-drop prerequisite, maps read, selected/opened counts, first-open failure, proc ownership/read-only/distinct/PID-1 facts, and descriptor closure;
- initial seccomp and NNP queries, NNP setting, filter installation, final mode, and fixed network policy;
- KVM absence/type/open/API-version/extension prerequisites and nullable values; and
- every aggregate cleanup boolean, uncertainty, case completeness, and outcome.

Exact map semantics are: a non-`ok` maps read has zero selected/opened counts and no open-failure record; an `ok` read has `0 <= opened <= selected <= 8`; the first-open failure is null exactly when all selected mappings opened; and every opened map descriptor must be proved closed. Initial seccomp mode and initial NNP become nullable and each has its own query status. No query failure is represented by zero. Successful filter installation requires successful NNP, final mode 2, and `fixed-eperm-filter-installed`; otherwise those downstream fields are null/blocked or the installation is mismatch as applicable. The combined proc case must actually compare the child-owned and parent proc views internally and emit only a nullable categorical distinction boolean, never mount or namespace identities.

`outcome="complete"` requires every fixed case to be categorically classified under this matrix, mandatory Python identity to be authenticated, all required observed fields to be present, every cleanup fact to be proved, every registry to be empty, and uncertainty to be false. It does not require every capability to be available. `unsupported`, `denied`, and correctly prerequisite-bound `blocked` cases can be complete. Any omitted, fabricated, contradictory, or unclassified fact forces safe `incomplete` or no report.

### 4. Baselines, deadline, process death, and exact cleanup

Replace optimistic booleans and module-global resource authority with one explicit owner and scripted adapter boundary. Before any effect, the outer unprivileged supervisor captures private exact baselines for:

- inherited descriptors and their stable identities/flags;
- owned children and descendants;
- mount table and current namespace identities;
- original soft and hard `RLIMIT_NOFILE`;
- the exact private-name root state;
- the clean exact checkout state already admitted by the workflow; and
- every owner registry.

A baseline that cannot be captured exactly permits no probe effect and no complete report. Baseline details remain private and may not add prohibited IDs, paths, fd numbers, process IDs, mount IDs, or namespace IDs to the report.

The workflow-bound topology has a fixed outer recovery supervisor and an effect worker. The outer supervisor performs no capability case itself, sets itself as the Linux child subreaper before creating the worker, and remains the exact recovery/reap authority for reparented descendants. Before release of the worker and every case child, sudo process, root helper, nested PID child, or exec child:

1. the parent registers the child and expected executable, session, process group, start-time identity, and pidfd before the next fallible effect;
2. the child sets `PR_SET_PDEATHSIG` to `SIGKILL`, verifies the expected parent is still alive, creates its fixed session/process-group relationship, closes or redirects all non-allowlisted descriptors, and sends a closed readiness record;
3. the parent revalidates identity and only then releases case work; and
4. any helper boundary that can clear parent-death state, including sudo/root transition, rearms and verifies it before case work.

If preparation or readiness fails, no case effect begins. Worker crash, signal, malformed record, partial startup, exec failure, or ordinary timeout is recovered by the outer supervisor. Loss of the outer supervisor, SIGKILL of that supervisor, job timeout, or unsafe codec failure emits no report. PDEATH contracts must prevent released descendants from continuing without the reviewed parent chain; runner disposal is never cleanup evidence.

Use one absolute 120-second supervisor deadline with a fixed cleanup reserve: no new non-cleanup effect begins after second 100, and all cleanup remains bounded by the absolute second 120 deadline. Every spawn, open, dup, pipe, read, hash chunk, write, syscall, status read, wait, and case loop checks the applicable absolute deadline before the effect. A deadline never degrades to a 1 ms allowance and never permits a later case. On expiry, close release/input gates and enter cleanup. There is no unbounded `waitpid`, read, write, hashing loop, TERM/KILL wait, or helper-input operation.

Cleanup preserves the primary result, attempts every independently safe reverse action, and aggregates all secondary failures. For each child it must:

1. close its release/input gate;
2. revalidate pidfd, start time, expected executable, session, and process group;
3. send TERM through exact retained identity;
4. wait to a fixed grace deadline;
5. revalidate and send KILL only if the same identity remains alive; and
6. wait and reap exactly, retaining the registry entry until reap is proved.

A PID, process group, process scan, exit code, or `ProcessLookupError` alone is not cleanup authority. Failure to signal, identify, wait, or reap is uncertainty. No potentially live child is discarded from the registry.

Authenticate `/` as the first fixed-tool chain component: it must be UID 0 and not group/world writable. Apply the same policy and stable-generation comparison to every later component, symlink, final object, and second walk. Register every descriptor before another fallible operation; aggregate every close result, including chain, replacement, pipe, selector, KVM, and temporary descriptors. Compare the final descriptor baseline exactly; a close error, fd reuse ambiguity, unexpected descriptor, or failed comparison prevents complete.

Create the fixed private root only if absent. Immediately open its parent and child with no-follow descriptors, verify exact type/mode/owner and generation, and retain fd-relative authority. Register every subname and its generation before use. Cleanup may unlink or `rmdir` only an exact registered generation relative to the retained parent descriptor. It may not adopt a pre-existing/replaced name, use an absolute cleanup path, global ownership boolean, recursive deletion, or infer success from absence.

Each mount is registered with its owning namespace and exact target/source generation before dependent work. Cleanup occurs only in that owning namespace after identity revalidation and uses no lazy, forced, or recursive unmount. Restore the original soft descriptor limit, compare mount/namespace/name/checkout/descriptor/child baselines, and prove every owner registry empty. Any foreign replacement, residual object, inability to compare, or cleanup deadline is terminal uncertainty.

After proved cleanup, repeated cleanup is a no-op. After poison or uncertainty, repeated cleanup repeats the same failure and cannot turn it into success.

### 5. Child output and isolation

Before any case code, every forked or execed case child must:

- change to fixed `/` or its exact private case directory, never retain the checkout as cwd;
- receive an empty fixed environment and no checkout path, token, ambient control, arbitrary argument, or caller-selected value;
- retain only fixed stdin and its bounded categorical result pipe; redirect stdout and stderr to bounded capture or `/dev/null` so neither Python/native crash text nor nested-child output can reach the job log;
- close every other inherited descriptor and prove the closed baseline before release; and
- install the fixed socket/io_uring filter before case work wherever technically possible under ADR 0087 C7.

The helper grammar is closed, strict UTF-8, one value, and bounded before allocation/read. Overflow, extra bytes, malformed JSON, duplicate keys, unexpected fields, noncanonical values, signal output, or any child stdout/stderr byte is mismatch/error plus safe cleanup, never public diagnostic output.

On success the workflow-bound probe emits exactly one canonical JSON line on stdout and no stderr. A safely classified ordinary failure may emit at most one canonical incomplete line and must fail. Bootstrap failure, outer-supervisor loss, SIGKILL, job/supervisor deadline, cleanup uncertainty that cannot be encoded safely, or codec failure emits no report and fails. The workflow shell never synthesizes facts.

### 6. Credential gate and workflow structure

Retain exactly three actual workflow steps, including unnamed steps in the count. Retain only the pinned checkout action and the fixed invocation accepted by ADR 0087.

Before the driver invocation, the non-repository shell gate must, without printing values:

- prove that `origin` is the only remote;
- inspect every fetch URL and every push URL and require each resolved value to be exactly the canonical credential-free HTTPS repository URL;
- reject every scoped or unscoped `http.*extraheader`, including exactly `http.extraheader`;
- reject every `credential.*` setting, `core.askPass`, nonempty `GIT_ASKPASS`/`SSH_ASKPASS` route, credential helper, and credential-bearing `remote.*.url` or `remote.*.pushurl` across all visible Git config scopes; and
- preserve the existing exact-head, clean tracked/untracked workspace, and source-head workflow/driver/schema blob checks.

The shell may hold a checked value only for comparison and must never echo a rejected key's value, URL userinfo, header, helper, token, or test canary. No credential-related value reaches `GITHUB_OUTPUT`, the driver, sudo, root helper, case child, later step, stdout, or stderr.

The workflow test must execute the exact extracted credential sub-gate in temporary Git repositories. It must prove the clean canonical fetch/push case passes and that each of these fails with its secret canary absent from stdout/stderr: unscoped extraheader, URL-scoped extraheader, credential helper, credential-bearing fetch URL, credential-bearing push URL, additional remote, and multiple URL entries. Static word searches are not evidence.

The workflow test must parse the actual `steps` sequence rather than count `- name:` lines. Hostile mutations must add an unnamed `run`, unnamed `uses`, nested action, second checkout, `always()`, `continue-on-error`, secret context, upload/cache/summary path, heredoc program, package/network command, retry, and fallback; every mutation must fail the static contract.

### 7. Required portable hostile tests

The private test mode may be selected only by an exact command-line mode that is disjoint from `--workflow-bound`; no environment, report field, fixture name, case list, timeout, path, fd, or policy can select it. Workflow-bound mode rejects optimized Python and every test/fault selector before any effect.

`test/runner-capability-probe.test.ts` must drive production state, codec, semantic, syscall, process, baseline, deadline, and cleanup control flow through a deterministic scripted adapter. A preassembled report fake and two aggregate booleans are insufficient. Without invoking real privileged/native effects, cover at least:

- success and complete mixed unsupported/denied/blocked reports;
- every allowed and forbidden status/errno/prerequisite/postcondition relation at every status-bearing field;
- upstream failure followed by correctly unattempted blocked dependents;
- every report bound, numeric boundary, nullable observation, map count, proc distinction, seccomp, KVM, sudo, namespace, temporary-file, O_PATH, descriptor, outcome, and cleanup relation;
- source/envelope values all distinct and mutations proving no forbidden equality;
- UID/GID-map rows, old keys, ID canaries, child output, environment, exception, path, maps, command, diagnostic, stdout, and stderr disclosure rejection;
- root-component and later symlink-chain success, loop, depth, owner, mode, replacement, short-read, generation, and size failures;
- deadline before and after every acquisition/effect, no post-deadline case start, fixed cleanup reserve, and no unbounded wait;
- open/dup/pipe/pidfd/fork/read/write/exec/readiness/PDEATH/status/TERM/KILL/wait/reap failures, malformed/overflow records, PID/fd reuse, identity mismatch, partial initialization, worker crash, and recovery from fresh outer-supervisor state;
- close, rlimit restore, unmount, unlink/rmdir, baseline compare, checkout compare, registry-empty, multiple simultaneous cleanup errors, repeat close after success, and repeat poisoned cleanup without false recovery;
- canonical determinism, strict UTF-8, duplicate keys, floats, noncanonical/reordered/extra/truncated/overlong data, exactly one LF, and the 32,768-byte report limit; and
- default invocation rejection, optimized-mode rejection, workflow-bound selector isolation, and proof that no real prohibited effect was reached.

The independent TypeScript semantics must mutate every fixed relation rather than import, call, transcribe, or trust the production validator's result table. Schema-only rejection does not count as semantic coverage. The workflow suite must perform the executable credential challenges and structural mutations in section 6.

Portable tests invoke no real sudo, namespace creation, mount, proc `map_files`, seccomp, KVM, `close_range`, `O_TMPFILE`, compression tool, network, container, provider, cloud, workflow, or production closure path.

### 8. Corrected capability highs

All accounting remains gross added physical lines from exact predecessor `bec0a19b0b984f88ab9c2effc5059f3737915caa`. Deletions, renames, generated content, compression, and code movement give no credit. Blank/comment lines count. Highs remain non-transferable.

Replace only ADR 0087's capability table with:

| Exact capability surface | Hard high |
| --- | ---: |
| `.github/workflows/outcome-two-runner-capability.yml` | 120 |
| `schemas/runner-capability-probe-v1alpha1.json` | 700 |
| `scripts/runner-capability-probe.py` | 1,900 |
| `test/runner-capability-probe.test.ts` (contract test) | 900 |
| `test/outcome-two-runner-capability-workflow.test.ts` (workflow test) | 160 |
| **Capability subtotal and hard high** | **3,780** |

The five highs sum exactly to 3,780. Unused allowance cannot cross a row or fund another capability or production surface. Stop for another ADR before crossing any row or aggregate high, adding a sixth implementation surface, moving driver/security behavior into YAML, moving production logic into tests, compressing readable control flow, or weakening any requirement here or in ADR 0087.

ADR 0087's separate Outcome 2 production, portable, native, and integration high remains exactly **7,000 gross physical lines**. No capability line, deletion, or unused allowance changes, funds, credits, or delays that production high.

### 9. Corrected verification and stop

Before implementation review, run the retained capability checks plus:

```text
/usr/bin/python3 -I -B scripts/runner-capability-probe.py --self-test
/usr/bin/python3 -I -B -O scripts/runner-capability-probe.py --self-test  # must reject with empty stdout/stderr
npx --no-install tsx --test test/runner-capability-probe.test.ts test/outcome-two-runner-capability-workflow.test.ts
npm run schemas
npm run format:check
npm run typecheck
git diff --check bec0a19b0b984f88ab9c2effc5059f3737915caa...HEAD -- \
  .github/workflows/outcome-two-runner-capability.yml \
  schemas/runner-capability-probe-v1alpha1.json \
  scripts/runner-capability-probe.py \
  test/runner-capability-probe.test.ts \
  test/outcome-two-runner-capability-workflow.test.ts
```

Also require ordinary `git diff --check` for the correction commit's changed files. Historical trailing whitespace in retained review input supplies neither a capability failure nor permission to rewrite review history.

After all checks pass at one exact clean correction head, obtain fresh workflow/credential, schema/semantics, driver/lifecycle, tests/fault-matrix, and holistic hostile reviews. Every P0–P3 finding must be resolved. Review must include measured gross additions for every row and the aggregate.

Then stop. This ADR does not supply the separate named approval required by ADR 0087 for one exact-head, exact-blob, exact-event, attempt-1, public-log observation. Do not apply the label, dispatch, rerun, or execute the capability workflow under this documentation decision. An eventual observation remains non-authoritative and cannot enable production work or select a fallback.

No production closure, parser, launcher, native Job A–E, thin integration, archive, Phase B, AWS, cloud, provider, OpenTofu, deployment, campaign, production, or issue-closure implementation or execution is changed or authorized by this amendment.

## Consequences

The capability report can retain useful categorical runner observations without disclosing UID/GID maps or collapsing external envelope identities into source identity. Exact semantic coupling prevents impossible complete reports. A fixed outer supervisor, pre-effect baselines, absolute deadlines, parent-death handshakes, closed child output, retained process/object identities, and fail-closed cleanup make one later effectful observation reviewable rather than relying on runner disposal.

The cost is 950 additional gross-line allowance, concentrated in the production driver and hostile contract tests. That allowance is capability-only. The trusted runtime-closure architecture, its 7,000-line implementation high, and every production and cloud stop remain unchanged.
