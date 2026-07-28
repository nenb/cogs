# ADR 0091 corrective plan — native common/workflow/schema

Status: design plan only; no implementation or execution is authorized by this document.

## 1. Planning identity and boundary

- Planning HEAD and five-report record head: `4eb9da3d2c98dd4a59e1e59817d34643bfba0d46`.
- Exact implementation reviewed by all five native-final-review reports: `ea6e74fe709e02061e13be78922da13a8cf6f748`.
- Gross-line accounting predecessor remains `bec0a19b0b984f88ab9c2effc5059f3737915caa`.
- Controlling predecessor is accepted ADR 0090, with non-conflicting ADR 0087–0089 rules retained.
- Inputs read in full: ADR 0090 and the five `native-final-review-{common,ab,cd,ei,holistic}.md` reports. The common code, schema, workflow, all six report producers, their focused tests, the schema registration suite, and the production A/B metadata and lease implementations were traced at HEAD.

ADR 0091 should authorize a closed source and portable/static correction only. It must grant no `--workflow-bound` invocation, native syscall qualification, sudo, namespace, mount, seccomp, `map_files`, compression execution, workflow dispatch/retry, cloud, provider, AWS, deployment, release, artifact reliance, or issue closure.

This plan closes the **common baseline, report, workflow, schema, A/B report-semantics, and portable-acceptance findings** in all five reports. It does not claim to close the independent production-owner findings for A/E/integration or the C/D process-mechanism findings. Those owners may consume the APIs fixed here, but their separate state-machine corrections still need their corresponding ADR 0091 plans and exact-head review.

No implementation file is added, renamed, generated, or moved. The only implementation surfaces in this slice are the already tracked workflow, native schema, common module, six native drivers, seven native companions, and the existing Outcome Two portion of `scripts/validate-schemas.ts`.

## 2. Finding-to-correction ledger

| Final report finding | Mandatory disposition in this plan |
| --- | --- |
| common P1: recovery has no retained generation authority, deletes replacement, and strands pre-publication crashes | Durable publication receipt, exact directory/file identities, crash-recoverable name-state machine, exchange-before-delete post-upload cleanup, and preserve-on-mismatch behavior in sections 5–7 |
| common P1: common accepts caller-supplied cleanup booleans | `NativeSession` owns the before snapshot and after observation; callers can only add monotonic uncertainty, never assert cleanup success (sections 3–4) |
| common P1 and AB/holistic P1: A metadata does not close role/order/provider/size/digest relationships | Exact A normalization and independently recomputed closure/mapping digests (section 8) |
| common/AB/holistic P1: B rewrites seal mask 63 to 15 | Schema and producer retain exact observed mask `63`; no report transform is permitted (section 8) |
| AB/holistic P2: B accepts two equal but wrong outputs | Both output digests must equal `sha256(b"cogs-runtime-qualification-v1\n")` (section 8) |
| AB/CD/EI/holistic P1: report cleanup unlinks by name after replacement | No destructive operation is selected from pathname alone; the receipt-bound exchange/capture state machine handles replacement and uncertainty (sections 6–7) |
| CD P1 and holistic P1: common/job fd snapshots use `os.listdir(fd)` and transient duplicate descriptors | One bounded `getdents64` implementation in common, through the exact enumerator lease, is the sole common snapshot implementation (section 3) |
| CD P2: C/D observe obsolete flat `.json` names | Fixed per-job path policy includes the real report directory and actual production root where applicable (section 3) |
| EI/holistic P1: E/integration observe `/run/cogs-o2-runtime-v1` while production owns `/tmp/cogs-o2-runtime-v1` | Common fixed path policy observes `/tmp/cogs-o2-runtime-v1`; E/integration cannot choose or replace that policy (section 3) |
| AB P1, CD P1, EI P1: outer wrappers allocate and retire descriptors without one-shot leases | Common `FdRegistry`/`FdLease` API, permanent close uncertainty, and no allocation after uncertainty (section 4) |
| common/EI/holistic P1/P2: portable acceptance is token matching and one happy path | Production state machines run against a complete scripted primitive matrix, schema registration gets six goldens/mutants, and workflow gates get executable pure models (sections 9–10) |
| common workflow test P1: event/dependency hostile cases are not modeled | Eligibility and final-result predicates move to effect-free common functions called by thin YAML and tested exhaustively (section 10) |
| ADR 0090 workflow obligations, reported positively by CD/EI/holistic | Preserve the literal selector, sibling topology, no artifact downloads, explicit failing eligibility, `always()` final job, fixed upload path, and mandatory cleanup; strengthen explicit upload/cleanup status carriage (section 10) |
| AB P2: fixed A/B mode routing is only token-tested | Portable bootstrap composition must route authenticated held bytes through each fixed mode and reject cross-mode result substitution; no native effect is reached (section 9) |

The common lease API also removes the current A/B/E/integration pipe-allocation leaks and close-before-guard pattern from native wrappers. It does not replace the production launcher/process owner; production owners remain responsible for their internal resources.

## 3. Common baseline ownership

### 3.1 Public API

Replace `WorkflowContext.from_environ(...)` followed by six driver-local snapshots with one entry:

```python
@dataclass(frozen=True)
class NativeSession:
    context: WorkflowContext

    @classmethod
    def begin(
        cls,
        expected_job: Literal["A", "B", "C", "D", "E", "integration"],
        driver_file: str | Path,
        *,
        ops: CommonOps | None = None,       # private portable injection only
    ) -> NativeSession: ...

    @property
    def fds(self) -> FdRegistry: ...

    def mark_uncertain(
        self,
        domains: tuple[CleanupDomain, ...],
        error: BaseException,
    ) -> None: ...                          # monotonic false veto only

    def settle_native_phase(self) -> CleanupEvidence: ...

    def publish(self, candidate: ReportCandidate) -> Path: ...
```

`ops` is accepted only by a private constructor used by imported portable tests; it is not selected by CLI, environment, driver arguments, or workflow. Production `begin()` always constructs `SystemCommonOps`.

The six drivers use exactly this shape:

```python
session = common.NativeSession.begin("A", __file__)
primary = None
try:
    observations = production_owner.run(session.fds)
except BaseException as error:
    primary = error
finally:
    try:
        production_owner.cleanup()
    except BaseException as error:
        primary = aggregate(primary, error)
        session.mark_uncertain(owner_domains(error), error)

evidence = session.settle_native_phase()
path = session.publish(common.ReportCandidate(checks, metadata, phase, diagnostics, primary))
```

A driver no longer passes `result`, `cleanup`, or a claimed pass/fail value. `ReportCandidate` contains only the fixed ordered checks, typed job metadata, bounded failure phase/diagnostics, and the primary error. `publish()` derives result and cleanup. A pass is possible only when all checks pass, `primary is None`, no domain is poisoned, and all seven before/after comparisons are exact.

`CleanupEvidence` has no public constructor and is bound to one session nonce and one use. `publish()` rejects evidence from another session, a second settlement/publication, or a session not in `RESTORED`/`FAILED_RESTORED`.

### 3.2 Fixed observations

`NativeSession.begin()` performs all source admission first and captures these exact values before returning authority to a driver:

```text
descriptors = ordered (fd, type, dev, ino, access mode, FD_CLOEXEC)
children    = direct child identities + owned-descendant census + self pgrp/sid/subreaper
paths       = fixed per-job path observations + report transaction names
mounts      = bounded complete mountinfo SHA-256
namespaces  = (user, pid, mnt, net) object identities
limits      = exact soft/hard RLIMIT_NOFILE
checkout    = HEAD, porcelain-v2 including untracked, local config, credential/remote policy
```

All observation reads are bounded, complete, strictly parsed, and stable across their required before/after `fstat` or identity check. An initial unknown/error aborts before job effects. An after-observation unknown/error sets only its named cleanup field false and is preserved in diagnostics; it can never become an unobserved success.

Descriptor enumeration is one common implementation:

1. open `/proc/self/fd` with `O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW`;
2. immediately register that number as `FdLease("fd-enumerator")`;
3. issue bounded `getdents64` repeatedly through that exact fd until EOF, with a fixed byte/record/fd-number bound;
4. reject malformed, duplicate, non-decimal, out-of-range, changing, or vanished live entries;
5. exclude exactly the enumerator fd, not any library duplicate;
6. `fstat` every returned live fd and capture the fixed fields; and
7. close the enumerator through its lease exactly once before returning the snapshot.

`os.listdir`, pathname `/proc/self/fd` scans, and fixed numeric-prefix scans are forbidden.

### 3.3 Fixed path policy

Drivers cannot supply cleanup paths. Common owns this closed table:

```python
NATIVE_PATHS = {
    "A": (),
    "B": ("/tmp/cogs-o2-runtime-v1",),
    "C": (),
    "D": (),
    "E": ("/tmp/cogs-o2-runtime-v1",),
    "integration": ("/tmp/cogs-o2-runtime-v1",),
}
```

Every job additionally observes its real fixed report directory and all common build/receipt/stage/slot/final names. Those names must be absent at `begin()` and again at native-phase settlement. Publication is a later, separate lease and therefore does not falsify the native cleanup report.

If a corrected production owner requires another named root, ADR 0091 must add that exact fixed path to this table; caller-selected, PID-derived, `/run` substitute, and obsolete flat `.json` paths are not accepted.

### 3.4 Baseline state machine

```text
NEW
  -- source/envelope/code admission + all before observations --> BASELINED
BASELINED
  -- begin returns to fixed driver ---------------------------> NATIVE_ACTIVE
NATIVE_ACTIVE
  -- owner cleanup starts ------------------------------------> NATIVE_SETTLING
NATIVE_SETTLING
  -- all after observations known ----------------------------> RESTORED
  -- mismatch/owner uncertainty/observation error ------------> FAILED_RESTORED
RESTORED | FAILED_RESTORED
  -- one ReportCandidate consumed ----------------------------> REPORT_PREPARING
REPORT_PREPARING
  -- exact durable publication -------------------------------> PUBLISHED
  -- pre-publication failure, no final name -------------------> REPORT_FAILED
  -- uncertain effect; recoverable receipt may remain --------> REPORT_UNCERTAIN
```

A native primary failure may still produce a canonical fail report only after all safe owner cleanup attempts and common after-observations. A common fd-close uncertainty during report preparation poisons publication: no later open is attempted in that process, no path is returned, and the workflow cleanup process performs receipt-based recovery.

## 4. Uncertainty and fd leases

### 4.1 Exact lease API

```python
class FdState(Enum):
    OWNED = auto()
    TRANSFERRED = auto()
    CLOSED = auto()
    CLOSE_UNCERTAIN = auto()

@dataclass
class FdLease:
    number: int
    purpose: str
    state: FdState = FdState.OWNED
    close_error: BaseException | None = None

    def close(self) -> None: ...
    def transfer(self, receiver: FdRegistry) -> FdLease: ...

class FdRegistry:
    def open(self, purpose: str, opener: Callable[[], int]) -> FdLease: ...
    def pipe2(self, purpose: str, flags: int) -> tuple[FdLease, FdLease]: ...
    def adopt(self, number: int, purpose: str) -> FdLease: ...
    def close_reverse(self, primary: BaseException | None) -> None: ...
```

Every successful allocation is registered before the next fallible action. `pipe2` registers both returned descriptors as one atomic allocation. `transfer()` creates receiver ownership and makes the sender permanently non-closing.

`close()` has these transitions only:

```text
OWNED -- close returns ----------------------> CLOSED
OWNED -- close raises before/after effect ---> CLOSE_UNCERTAIN(error)
CLOSED -- close -----------------------------> no-op
TRANSFERRED -- close ------------------------> reject
CLOSE_UNCERTAIN -- close --------------------> raise the same stored error, no syscall
```

Before invoking the syscall, the registry marks that a close is in flight. If it raises, the descriptor number is retired permanently. The process performs no subsequent allocation/reopen, never retries or probes that number, and only closes already registered, independently safe leases with different numbers. A candidate allocation equal to any retired number is terminal and is not closed by the uncertain owner. Primary and cleanup failures remain ordered in one aggregate.

This rule applies to baseline enumerators, report/receipt/slot objects, directory fds, A/B/E/integration outer pipes, source roots, pidfds, and every common test adapter. Driver-local raw fd sets and “remove before close” are deleted.

### 4.2 Uncertainty is monotonic

`mark_uncertain()` can only force named cleanup domains false. It cannot set a domain true or replace a common observation. Common automatically poisons `descriptors` on any `FdLease.CLOSE_UNCERTAIN`, `children` on process-owner uncertainty, and `paths` on publication/name uncertainty. A later matching snapshot cannot erase the poison.

An uncertain publication operation is resolved only from durable names and receipt in a fresh cleanup process. It is never resolved by retrying the uncertain descriptor or assuming the action happened.

## 5. Durable publication format

The fixed external artifact remains exactly:

```text
/tmp/cogs-native-qualification-<job>/report.json
```

The private mode-0700 directory may also contain these fixed hidden transaction names, none of which is uploaded:

```text
.owner.json       durable canonical ownership receipt
.report.stage     linked validated report before publication
.cleanup.slot     receipt-bound regular-file exchange placeholder
report.json       the only upload path
```

The receipt is a closed canonical record with:

```text
version = cogs.native-report-publication/v1
job, workflow job ID, run ID, run attempt, head SHA
report canonical SHA-256 and exact size
report FileIdentity
slot FileIdentity
report-directory DirectoryIdentity
common/driver/workflow/schema blob SHA-256 values
fixed inventory and transaction version
random 256-bit transaction nonce (identification, not ambient trust)
```

`FileIdentity` is the stable object key `(mount-id, device-major, device-minor, inode, regular-type, uid, gid)` plus phase-checked `(mode, nlink, size, mtime_ns, ctime_ns)` and content SHA-256. `DirectoryIdentity` uses the corresponding directory key, mode `0700`, exact owner, and parent-mount relationship. A pathname stat, digest alone, or inode alone is insufficient.

The report and exchange slot begin as `O_TMPFILE|O_CLOEXEC` objects under the held exact directory. They are fully initialized, fsynced, and identified before gaining names. The receipt likewise begins anonymous, is completely written/fsynced/reopened/validated, and is linked no-replace as the first durable named intent. Unsupported `O_TMPFILE`, `linkat(AT_EMPTY_PATH)`, `renameat2`, `statx` identity, no-replace, or directory fsync fails closed; there is no pathname-only fallback.

The only unavoidable crash window before the receipt is an exact empty mode-0700 directory created from an absent fixed baseline. Recovery may remove it only when it is empty, has the fixed owner/mount/type/mode, and no transaction name. A nonempty receipt-less directory is preserved as foreign/uncertain and fails cleanup.

## 6. Publication state machine

`NativeSession.publish()` performs this exact sequence:

1. Derive seven cleanup booleans from the sealed common evidence. Apply monotonic uncertainty vetoes. Derive `result`, failure phase, and diagnostics digest; callers do not supply coupling fields.
2. Build canonical bytes in memory. Apply the tracked JSON Schema and the independent semantic validator.
3. Require the fixed report directory and all transaction names absent. Open and retain exact `/tmp` parent authority; create/open/validate/fsync the private directory.
4. Create anonymous report and slot objects and register both leases. Completely write the report with an EINTR-aware loop; zero progress is terminal. `fsync`, `fstat/statx`, enforce regular `0600`, owner, bound, and complete generation.
5. Reopen the anonymous report through a distinct read-only authority, completely read it, require byte equality, and independently repeat canonical decode, schema, and semantics. Close that lease certainly.
6. Construct the receipt from the now-known report, slot, directory, and code identities. Write/fsync/reopen/validate the anonymous receipt.
7. Link the receipt no-replace to `.owner.json`; fsync the directory. Only after this write-ahead intent may named report state exist.
8. Link report to `.report.stage` and slot to `.cleanup.slot`, each no-replace, with identity readback and directory fsync after each durable transition.
9. Close the original anonymous writable leases certainly. Reopen `.report.stage` read-only, compare the receipt-bound identity/bytes, and repeat independent schema and semantics.
10. Publish with `renameat2(.report.stage, report.json, RENAME_NOREPLACE)`. Fsync the directory.
11. Reopen `report.json`, compare exact receipt identity, bytes, schema, semantics, context, and absence of `.report.stage`; close certainly.
12. Close directory and parent leases certainly. Only now return the fixed `Path` and permit a successful driver exit.

Legal durable name states are closed:

```text
D0: directory absent
D1: exact empty private directory
D2: owner only
D3: owner + stage
D4: owner + stage + slot
D5: owner + final + slot          # published/uploadable
C1: owner + slot(report) + final(slot)  # cleanup exchange completed
C2: owner + final(slot)           # report removed
C3: owner only
D0: restored
```

No other inventory is normalized. Both source and destination after a before/after-effect rename fault are inspected from a fresh process against the receipt. Exactly one matching location is accepted; both, neither, an extra name, or identity drift is terminal uncertainty. Before publication, recovery may remove only receipt-bound stage/slot objects and must prove final absent. After publication, recovery enters the cleanup machine below.

A directory-fsync error after an effect is uncertain, not success. The current process does not reopen after a close uncertainty. A successful publication followed by a close uncertainty is not exposed; the fixed cleanup step recovers it and the native job remains failed.

## 7. Identity-bound post-upload cleanup

The workflow always invokes only:

```text
/usr/bin/python3 -I -B scripts/native-qualification/common.py --cleanup <fixed-job>
```

`cleanup_report(job)` opens the parent and directory no-follow, validates exact directory identity/policy, opens and validates `.owner.json`, and classifies the complete fixed inventory. It never unlinks first and reasons later.

For state D5 it performs:

1. Open/validate final report and slot against the receipt. Reapply canonical, schema, semantic, and context validation to final bytes.
2. Atomically `renameat2(report.json, .cleanup.slot, RENAME_EXCHANGE)`. This captures the object occupying the upload name and installs the known slot object at the upload name without deleting either.
3. Reopen both names. Require `.cleanup.slot` to be the receipt report and `report.json` to be the receipt slot. If either is foreign, attempt one exact reverse exchange only while both current identities match the just-observed exchange state. Preserve the foreign object and all evidence; report terminal uncertainty.
4. Unlink `.cleanup.slot` only after immediate retained-directory identity comparison proves it is the receipt report. Fsync the directory (C2).
5. Unlink `report.json` only after proving it is the receipt slot. Fsync the directory (C3).
6. Unlink `.owner.json` only after proving its exact canonical receipt identity. Fsync the directory.
7. Close directory certainly, `rmdir` the exact empty directory through retained parent authority, fsync parent, close parent certainly, and prove every original report-namespace path absent.

A cleanup crash is recoverable from D5/C1/C2/C3 by receipt identities. A pre-publication crash at D1–D4 removes only the exact empty directory or receipt-bound owned names, proves `report.json` absent, and restores the baseline. If upload fails, the same machine runs; upload status changes final gate status, not identity policy.

Replacement, extra inventory, malformed receipt, current/receipt identity mismatch, failed reverse exchange, unlink-before/after uncertainty, fsync uncertainty, nonempty rmdir, parent drift, or inability to prove absence is failure. Foreign state is preserved. “Restored-looking after deleting a replacement” is impossible by construction.

## 8. Closed schema and independent A/B semantics

### 8.1 Schema corrections

Retain the six-way job union and pass/fail union, but make these exact changes:

- B `seal_mask` is `const: 63`, matching `_EXEC_SEALS`; producer copying is byte-for-value and may not rewrite it.
- A object `size_bytes` maximum is `134217728` (`128 MiB`), matching the production object bound.
- A metadata order is fixed: one executable, one loader, zero or more libraries, then exactly one summary. Object IDs are exactly `python-object-0` through the corresponding index. Libraries cannot precede or replace the first two roles.
- A `needed` entries are unique at the semantic layer; schema retains closed bounded label arrays. A libraries require non-null SONAME.
- B metadata remains exactly ordered gzip then zstd and exact two rows. Sizes retain the production object bound; all eight fields are required and closed.
- All six check arrays remain exact ordered prefix arrays with fixed cardinality and no extra items. Pass/fail cleanup/failure coupling remains closed.
- Failure metadata remains the exact empty array for A/B/E/integration; no partial authority metadata is published from a failed transaction.

JSON Schema handles structural closure. It is not used to pretend provider resolution or digest relations are expressible.

### 8.2 Independent A semantics

Common reconstructs the production-normalized object sequence from each artifact object by dropping `kind/id` and renaming `size_bytes` to `size`:

```json
{"needed":[...],"role":"...","sha256":"...","size":N,"soname":"..."}
```

It independently requires:

1. roles exactly `[executable, loader, library*]` and IDs exactly match indices;
2. 2–127 objects, each size `1..134217728`;
3. unique `(sha256,size)` identities and no digest with conflicting role;
4. each `needed` list unique and ordered exactly as observed;
5. each library has one unique SONAME; all needed names have exactly one provider;
6. libraries strictly sorted by `(SONAME ASCII bytes, sha256)`;
7. `summary.closure_sha256 == sha256(canonical(normalized_objects))`; and
8. `summary.mapping_sha256 == sha256(canonical([[role,sha256], ...]))`.

Canonical here is UTF-8 JSON with sorted keys, compact separators, no NaN, and no LF inside the digest input—the exact production `_canonical` formula. The semantic implementation must not call the A producer's `qualify()` or production report decoder.

The A producer independently recomputes both formulas from the admitted production result and rejects disagreement with its supplied summaries before creating metadata. Thus arbitrary copied summary digests cannot pass either side.

### 8.3 Independent B semantics

For ordered gzip/zstd rows, common and the B producer independently require:

- source and sealed SHA-256 equal per tool;
- source and sealed size equal per tool and within `1..134217728`;
- exact observed seal mask `63` in production result and report;
- each execution-mapping digest is a valid production observation and is not substituted across tool IDs;
- each row output equals its matching top-level production output; and
- both outputs equal `sha256(b"cogs-runtime-qualification-v1\n")`, not merely each other.

The report stores the actual observed `63`. No normalization to a historical four-seal mask exists.

### 8.4 General schema registration

The existing Outcome Two allowance in `scripts/validate-schemas.ts` registers one valid pass and one valid fail sample for each of A, B, C, D, E, and integration. It applies isolated mutations for job/job-ID mismatch, check missing/extra/order/duplicate/outcome, cleanup contradiction, failure coupling, source/envelope mismatch, metadata missing/extra/type/order, A role/provider/size/needed/summary, B seal/source/size/mapping/output, E policy, and integration field substitution.

The common companion sends the same six goldens and semantic mutants through production `_validate_schema` and `_validate_semantics`. AJV acceptance alone is not semantic acceptance, and invoking either producer codec is forbidden.

## 9. Complete portable primitive/fault matrix

`test/native-qualification-common.test.ts` drives the real `NativeSession`, baseline owner, report codec, publication state machine, and recovery state machine through a private scripted `CommonOps`. It does not replay a parallel transcript. Every operation records `requested`, `effect`, `result`, state before/after, and live object/lease inventory. Every named fault has a branch-removal sentinel.

For every fallible operation below, the matrix includes **before-effect error**, **after-effect error/uncertainty**, and **process-crash after a successful durable effect** where an effect exists:

| Area | Exact cuts/mutations |
| --- | --- |
| baseline fds | open enumerator, every `getdents64` batch, malformed record, duplicate/name bound, vanishing/live fd, fstat identity drift, enumerator close, close+fd reuse |
| other baselines | child/descendant read and parse, process identity drift, mountinfo short/overflow/drift, each namespace open/stat/readlink, getrlimit, each fixed path absent/present/error, HEAD/porcelain/config/remote read and mismatch |
| report value | duplicate JSON key, non-ASCII/noncanonical/framing/size, first and second schema divergence, first and second semantic divergence, context/code hash drift, canonical re-encode drift |
| allocation/write | parent/directory open, mkdir, directory validation, each `O_TMPFILE`, short/zero/EINTR writes at every offset, fchmod/fstat/statx drift, file fsync, read-only reopen, short/zero/EINTR read, every file close before/after and reuse |
| durable intent | receipt encode/reopen/validation, receipt link collision, stage link collision, slot link collision, identity mismatch after each link, directory fsync before/after each durable transition |
| publication | final preexistence/collision, `RENAME_NOREPLACE` before/after effect, stage/final both-or-neither, final reopen/read/schema/semantic/canonical mismatch, publication directory fsync, directory/parent close uncertainty |
| crash recovery | crash at D0, D1, D2, D3, D4, D5, C1, C2, and C3; restart classifies only the legal receipt-bound inventory and is idempotent from every certain state |
| post-upload cleanup | report absent, upload success/failure, directory/receipt/final/slot replacement, extra name, exchange before/after, wrong captured identity, safe reverse exchange and reverse failure, every unlink before/after, every fsync before/after, rmdir nonempty/replacement, parent fsync, final absence proof |
| lease poisoning | close-before-effect, close-after-effect, same-number reuse candidate, repeated close, transfer then close, aggregate primary plus multiple independent cleanup errors, attempted allocation after uncertainty |

The matrix oracle permits only:

```text
A. one exact canonical/schema/semantic/context-validated D5 publication,
   followed by exact receipt-bound cleanup and D0 baseline restoration; or
B. no exposed final path, terminal failure, and either proved D0 restoration or
   explicitly preserved foreign/uncertain state that makes cleanup/final gate fail.
```

It never accepts deletion of a foreign generation, a second publication, reuse/retry of an uncertain fd, a pass with unknown cleanup, or a path returned before all validation and certain closes.

The focused A/B tests additionally drive authenticated fixed bootstrap mode routing, exact A digest/provider semantics, exact B mask/output semantics, and cross-mode substitution. C/D/E/integration companions verify they call `NativeSession.begin`, use its fd registry for wrapper resources, cannot submit cleanup maps, and use the fixed actual path policy. These portable calls reach no native primitive.

## 10. Workflow architecture and executable gate tests

### 10.1 Thin common predicates

Add two effect-free common functions with exact environment records:

```python
def evaluate_eligibility(env: Mapping[str, str]) -> None: ...
def require_final_results(env: Mapping[str, str]) -> None: ...
```

`evaluate_eligibility` accepts only the fixed keys and only a same-repository `pull_request`, attempt `1`, canonical required SHAs, positive PR/run IDs, and exact repository relation. Any missing, extra, malformed, fork, push, or later-attempt value raises and exits nonzero before a native job can run.

`require_final_results` accepts individually named values, not `join(needs.*.result)` ordering. It requires:

- Quality and eligibility result `success`;
- A–E and integration job result `success`;
- each of six upload step outcomes `success`; and
- each of six cleanup step outcomes `success`.

Empty, unknown, failed, cancelled, or skipped is failure.

### 10.2 YAML wiring

- Eligibility always runs and invokes only `common.py --eligibility` with the exact isolated event environment.
- A–E remain fresh sibling jobs needing Quality and eligibility. Integration remains a sixth fresh job needing eligibility and A–E, and downloads no A–E artifact.
- All six production invocations retain literal `--workflow-bound` and exact isolated environments.
- Upload steps receive fixed IDs and fixed report paths. Cleanup steps receive fixed IDs, run under `always()`, and invoke only `common.py --cleanup <job>`.
- Each native job exports its upload and cleanup step outcomes as job outputs. A skipped upload yields empty/not-success; it cannot be inferred successful.
- The final required job retains `if: always()` and passes all eight job results plus twelve step outcomes under individually named environment keys to `common.py --require-final-results`.
- Branch protection continues to require only the final native qualification result, not a conditionally skipped leaf.

### 10.3 Portable workflow matrix

The common companion parses the six YAML blocks and fixed CLI dispatch, then directly executes the two pure predicates for:

- valid same-repository attempt 1;
- attempt 2 and larger;
- fork PR, push, missing event, missing/extra field, malformed SHA/repository/number;
- each dependency independently `failure`, `cancelled`, `skipped`, empty, and unknown;
- each upload independently failed/skipped/empty;
- each cleanup independently failed/skipped/empty; and
- all-success.

It also proves ineligible cases cannot select a native driver, every YAML selector is `--workflow-bound`, every incompatible selector rejects before effects, artifact/report/job identities agree, integration has no artifact download, and no upload uses wildcard or `always()`.

## 11. Implementation order and acceptance

1. Accept ADR 0091 with this closed API, state machines, fault matrix, and highs; do not run anything as part of the decision commit.
2. Implement common baseline/lease primitives and pure workflow predicates behind scripted portable ops.
3. Replace six caller-owned cleanup maps/snapshots with `NativeSession`; remove obsolete `/run`, flat `.json`, `os.listdir(fd)`, raw fd-set, and prefilled cleanup routes.
4. Implement durable publication/recovery and the full fault matrix before enabling the system-ops happy path in acceptance.
5. Close schema and A/B producer/semantic relationships; add six general schema goldens and isolated mutants.
6. Wire explicit workflow step outcomes and final named-result predicate.
7. Run only ordinary portable/static gates under ADR 0091 authority. Do not invoke a workflow-bound/native selector.
8. Obtain fresh independent common/workflow, schema/report, A/B semantics, fault/recovery, and holistic exact-head hostile reviews. Resolve every P0–P3 finding.
9. Seek a later ADR naming the clean reviewed head before any native attempt.

Acceptance requires source review plus the complete portable oracle. Token search, one Linux happy-path report, AJV-only validity, a caller-created all-true cleanup map, and runner disposal receive no credit.

## 12. Revised realistic gross-line highs

All values count gross added physical lines from `bec0a19b0b984f88ab9c2effc5059f3737915caa`. Blank/comment lines count. Deletion, rename, generated data, compression, binary, and code-movement credit are forbidden. Highs are non-transferable and one line may not hide multiple fallible effects or cleanup decisions.

The estimates below allocate approximately 230 formatted lines for common baseline/lease ownership, 220 for report codec/semantics, 330 for publication/recovery, and 620 for the scripted operation/state matrix. ADR 0090's 400-line common and 200-line common-test highs cannot honestly hold this correction; both are already essentially full at the reviewed head.

| Existing exact surface | Reviewed gross | Planned final gross | ADR 0091 hard high |
| --- | ---: | ---: | ---: |
| `.github/workflows/ci.yml` Outcome Two addition | 250 | 290 | 330 |
| `schemas/native-qualification-report-v1alpha1.json` | 293 | 360 | 400 |
| `scripts/native-qualification/common.py` | 400 | 760 | 850 |
| `scripts/native-qualification/job-a-runtime-mappings.py` | 300 | 260 | 320 |
| `scripts/native-qualification/job-b-compression.py` | 341 | 285 | 360 |
| `scripts/native-qualification/job-c-descriptors.py` | 250 | 190 | 250 |
| `scripts/native-qualification/job-d-process-lifecycle.py` | 350 | 300 | 360 |
| `scripts/native-qualification/job-e-sandbox.py` | 449 | 330 | 450 |
| `scripts/native-qualification/thin-integration.py` | 350 | 270 | 350 |
| `test/native-qualification-common.test.ts` | 197 | 620 | 700 |
| `test/native-qualification-a.test.ts` | 98 | 140 | 170 |
| `test/native-qualification-b.test.ts` | 111 | 150 | 180 |
| `test/native-qualification-c.test.ts` | 91 | 120 | 150 |
| `test/native-qualification-d.test.ts` | 112 | 145 | 180 |
| `test/native-qualification-e.test.ts` | 112 | 160 | 200 |
| `test/native-qualification-integration.test.ts` | 107 | 150 | 190 |
| **Native planned / individual-high sum** | **3,811** | **4,530** | **5,440** |

The independently binding native subtotal hard high should be **5,200**, so at least 240 lines of individual ceilings must remain unused. The planned 4,530 leaves 670 lines (14.8%) for readable correction without authorizing all per-file highs simultaneously.

Raise only the existing `scripts/validate-schemas.ts` Outcome Two registration allowance from 30 to **120** gross lines. All other trusted/portable ADR 0090 highs remain unchanged. The trusted/portable subtotal therefore rises from 8,930 to **9,020**.

The binding trusted/portable and native subtotals total **14,220**. Set the Outcome Two aggregate hard high to **14,300**, leaving an 80-line non-transferable aggregate margin. The separate capability-probe allowance remains unrelated and supplies no credit.

Stop and adopt another ADR before crossing a file, native subtotal, trusted/portable subtotal, or aggregate high; adding/renaming a surface or dependency; introducing a publication fallback; changing report disclosure, job topology, source trust, cleanup domains, or authority model; or moving behavior into YAML, schema, fixtures, generated data, or compressed control flow.

## 13. Resulting decision statement

ADR 0091 should supersede ADR 0090 only for common baseline ownership, fd uncertainty, report publication/recovery, post-upload cleanup, native report A/B semantics, executable workflow gate predicates, portable acceptance, and the numeric highs above. ADR 0090's no-native/no-cloud gate, fixed jobs, trusted production ownership requirements, report disclosure boundary, and all non-conflicting rules remain in force.

The corrected architecture has one owner for common cleanup facts, one permanent fd-uncertainty rule, one durable identity-bound report transaction, one exact schema/semantic authority, and one explicit final workflow result. It still provides no native evidence until a later accepted execution ADR names a clean reviewed head.
