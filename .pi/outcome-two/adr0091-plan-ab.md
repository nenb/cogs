# ADR 0091 corrective architecture plan — admitted A/B production owners

Status: proposed design only. This record authorizes no implementation or execution.

Planning head: `4eb9da3d2c98dd4a59e1e59817d34643bfba0d46`.
Reviewed implementation head: `ea6e74fe709e02061e13be78922da13a8cf6f748`.
Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`.

## 1. Scope and disposition

This plan addresses the Job A, Job B, admitted-bootstrap, source-topology, production-launcher, and A/B outer-lifecycle findings in all five final reports:

- `.pi/outcome-two/native-final-review-ab.md`;
- `.pi/outcome-two/native-final-review-cd.md`;
- `.pi/outcome-two/native-final-review-common.md`;
- `.pi/outcome-two/native-final-review-ei.md`; and
- `.pi/outcome-two/native-final-review-holistic.md`.

The reviewed head remains blocked. In particular, it is not acceptable to repair the report while retaining a substitute owner, or to expose a private helper composition and call it a production API.

This A/B slice does not claim to close the common report-generation transaction, C/D, E, or thin integration. Their final-review findings remain mandatory parallel prerequisites to any native authority. The common baseline/publication correction must land before A/B can publish authoritative reports. E must later use the source topology in section 6 and a separate fixed sandbox-only entry; it may not reuse B merely because B uses the launcher.

No native selector, workflow attempt, sudo, namespace, mount, seccomp, `map_files`, compression executable, cloud, provider, AWS, deployment, release, or production operation is authorized by this plan.

## 2. Controlling design choices

1. **Public owner, private primitives.** A bootstrap mode terminates at one named public production-owner entry. Private resolver, helper, map, issuer, root, and process methods remain implementation details and are never composed by a job, bootstrap dispatcher, or portable test.
2. **Admission before owner entry.** The public entries are callable only in the exact synthetic modules loaded from the held authenticated source set. An ambient import has no admitted one-shot module state and rejects before its first authority-bearing operation.
3. **Zero policy arguments.** The entries take no path, root, fd, tool, command, mode, timeout, report, namespace, or policy argument. Fixed mode selection occurs only in the admitted bootstrap's closed dispatch table.
4. **A is mapping-only.** A does not create a user/mount namespace, bind `/run`, create a preparation root, resolve gzip/zstd, seal an object, issue a handoff, or enter T2.
5. **B is the real production transaction.** B uses the same closure, sealing, issuance, materialization, T2, exec, mapping, observation, and cleanup owners as the ordinary production qualification. It is not a metadata-only shortcut around them.
6. **Outer launch is evidence, not disposal.** A/B drivers own the isolated bootstrap process and every setup descriptor through one bounded transaction. The inner production owner's cleanup does not excuse an outer leak, and runner teardown is never evidence.

## 3. Fixed admitted public entries

### 3.1 Job A owner

`completion_trusted_runtime_closure.py` exposes this public production entry in the admitted synthetic module:

```python
def qualify_fixed_python_mapping() -> RuntimeMappingQualificationResult: ...
```

It is a zero-argument, one-shot owner entry. It consumes module-local admission installed by the bootstrap after exact source authentication. A second call, an ambient import, a module copy, a different synthetic package, or missing admission fails before fd enumeration, source open, helper creation, or proc access.

The closure module, not the launcher or Job A, owns the complete mapping transaction. The existing launcher-side `_MappingAuthority` and `_coordinate_admitted_mapping_only` compositions are deleted. The public function may use private closure primitives internally, but their order, cleanup, and result construction are controlled by one closure production state machine.

### 3.2 Job B owner

`completion_trusted_runtime_launcher.py` exposes:

```python
def launch_fixed_compression_qualification() -> RuntimeCompressionQualificationResult: ...
```

This is also zero-argument and one-shot. It consumes the bootstrap-installed admitted context and invokes the actual production closure and launcher owners. It does not accept a handoff assembled by the caller and does not return the ordinary result with a dictionary field appended.

The ordinary integration entry remains a distinct closed entry:

```python
def launch_fixed_runtime_qualification() -> RuntimeQualificationResult: ...
```

Its exact frozen result is unchanged by adding A/B. Compression-only metadata exists only in `RuntimeCompressionQualificationResult`. A later E correction must add/use the already specified zero-argument `launch_fixed_sandbox_probe()`; neither A nor B is that probe.

### 3.3 Bootstrap dispatch

The admitted bootstrap has a closed version-to-entry table:

| Admission version | Sole public entry | Closed result |
| --- | --- | --- |
| `cogs.runtime-source-admission/v1` | `launch_fixed_runtime_qualification` | `RuntimeQualificationResult` |
| `cogs.runtime-source-admission/mapping-v1` | `qualify_fixed_python_mapping` | `RuntimeMappingQualificationResult` |
| `cogs.runtime-source-admission/compression-v1` | `launch_fixed_compression_qualification` | `RuntimeCompressionQualificationResult` |

The table contains public callables, not labels followed by private `if` branches. Bootstrap authenticates all fixed source bytes, loads the exact synthetic modules, installs one admission, resolves exactly one table entry, calls it once, validates the exact result type and field inventory for that mode, emits one bounded canonical line, and consumes the admission even on failure.

A mode may narrow work only as specified here; it may not weaken source admission, fixed Python identity, fd ABI, cleanup, or result framing. Cross-mode result substitution is an exact typed failure.

## 4. Minimal Job A mapping transaction

The closure owner performs this sequence and no more:

```text
consume exact admitted mapping capability
  -> architecture gate and exact fd/child baselines
  -> resolve/authenticate fixed /usr/bin/python3 closure
  -> create one fresh helper blocked behind the production release gate
  -> preregister helper pidfd and complete identity
  -> release helper
  -> read complete maps, open every executable map_files object
  -> require exact resolved/mapped role and generation equality
  -> reread maps byte-for-byte and require stability
  -> boundedly stop/reap the helper
  -> close every proc/map/source descriptor once
  -> restore exact fd/child baselines
  -> construct the closed observed result
```

The result contains:

- fixed version `cogs.runtime-mapping-qualification/v1`;
- admitted source revision and source-set digest;
- exactly one `python3-parser` tool;
- complete ordered object rows: executable first, loader second, then libraries in the trusted-report order;
- for every object: role, size in `1..134217728`, SHA-256, nullable SONAME, and ordered unique `DT_NEEDED`;
- per-tool closure digest recomputed over the canonical object array;
- mapping digest recomputed over the actual stable mapped `[role, sha256]` sequence; and
- individually observed mapping stability, generation equality, helper reap, descriptor restoration, and child restoration facts.

The owner and Job A both require one executable, one loader, only libraries thereafter, unique dependency names, exactly one provider for every dependency, no extra provider/object, no duplicate authenticated identity, at most 128 objects, and the accepted aggregate byte bounds. The driver recomputes the two summary digests from the returned rows instead of copying arbitrary 64-hex strings. The common semantic validator independently repeats the artifact-level relationships.

A has no private root. Removing its current user/mount namespace setup and unused bind of a job directory onto `/run` is a contract requirement, not an optimization.

## 5. Exact Job B transaction and metadata

B invokes the real compression entry and requires both fixed tools in exact order `gzip`, `zstd`. Success requires the complete ordinary production observation conjunction plus the following tool evidence.

For each tool, the closed result and native report bind:

- the complete ordered closure object vector, with role, size, SHA-256, SONAME, and ordered unique `DT_NEEDED` for executable, loader, and every library;
- the recomputed per-tool closure digest;
- source executable size and SHA-256;
- sealed executable size and SHA-256, equal to that source generation;
- exact seal mask **63**, representing `SEAL|SHRINK|GROW|WRITE|FUTURE_WRITE|EXEC`;
- the actual final execution-mapping digest, recomputed over and equal to the complete expected closure mapping vector;
- exact deterministic output digest; and
- the top-level trusted closure digest binding the admitted report used by execution.

The fixed output is exactly `b"cogs-runtime-qualification-v1\n"`. Both tool outputs must equal those bytes, and each published digest must equal:

```text
6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8
```

Equality of the two digests alone is insufficient. A producer value other than that constant rejects even if both tools agree.

The `63 -> 15` rewrite is deleted. The native schema fixes `seal_mask` to 63, the B golden and every shared B fixture use 63, and producer, common semantics, and portable tests reject 15, any other subset/superset, or a mismatch with the production observation. No private fd, path, PID, source generation, map row/address, inode/device value, or raw bytes enter the report.

B does not create or mount a driver-selected preparation root. The production launcher alone owns fixed `/tmp/cogs-o2-runtime-v1`, its retained parent/root generations, mounts, namespace handles, and exact removal. The driver independently observes that actual production path in its outer baseline.

## 6. Source-root and execution topology

A/B use this topology:

```text
runner-owned exact-head checkout
  ├─ retained source-root directory fd (fd 4 in the bootstrap ABI)
  └─ retained no-follow launcher fd (executed as that held generation)
       -> fixed /usr/bin/python3 -I -B, empty environment
       -> canonical admission on fd 3
       -> admitted source bytes loaded from fd 4
       -> selected public production owner
```

The child must not execute `completion_trusted_runtime_launcher.py` by checkout pathname. The unprivileged outer owner opens and authenticates the launcher generation under the exact source-root authority, retains it through exec, and asks fixed Python to execute that held descriptor generation. The T0 workflow/source gate is the external admission of the initial bootstrap bytes; the bootstrap then authenticates parser, closure, launcher, and schema held bytes against the exact Git tree before loading parser/closure or performing an owner effect.

The source root is deliberately runner-owned for unprivileged A/B, and the bootstrap effective UID is the runner UID. It must be one retained directory generation, not group/world writable, and match the exact admitted checkout. It is not renamed “root-owned” and is not reused as T2 or preparation-root authority.

The production state root is separate. For B it is the fixed launcher-owned `/tmp/cogs-o2-runtime-v1`; for A it does not exist. No A/B driver creates `/run` state or passes a caller-selected state path. A future sudo E route must authenticate/load the runner-owned source set before privilege crossing and pass an admitted immutable source bundle to the root process; it must not require the runner checkout directory itself to be UID-0-owned. This closes the topology contradiction identified by the E and holistic reviews without granting E implementation scope here.

## 7. Bounded A/B outer process and fd owner

Each driver replaces raw `_child`, `_wait`, and `_launch` cleanup with one small fixed bootstrap-owner state machine. It may be duplicated only as typed A/B wiring; primitive lifecycle behavior must be byte-for-byte shared through an already authorized production/common primitive or proved equivalent by the same portable contract. It must not be hidden in workflow YAML.

### 7.1 Descriptor transaction

- Every successful `open`, `pipe2`, `socketpair`, duplicate, and pidfd acquisition is inserted into an `OWNED` lease before the next fallible operation.
- Allocation failure closes every earlier lease in reverse order and aggregates uncertainty.
- Lease states are exactly `OWNED -> CLOSED | TRANSFERRED | CLOSE_UNCERTAIN`.
- A close is attempted once. An after-effect error retires the number permanently; no later open, cleanup, or report operation may reuse or close that uncertain number.
- Child-end transfer is explicit. Parent ends, admission input, held launcher, source root, result/status channels, release gate, and pidfd each have one named owner.
- Result and error/status streams have independent byte bounds. EOF never cancels the process deadline.

### 7.2 Process transaction

- Creation uses a blocked child and obtains pidfd authority before release. The child performs only fixed session/process-group setup and the preregistration handshake while blocked.
- Before release the outer owner records PID, pidfd, start time, executable identity, expected post-exec fixed-Python identity, session, process group, release/status descriptors, and descendant baseline.
- A clean CLOEXEC exec-status EOF proves transition to the fixed Python generation; the outer owner then revalidates identity before accepting output.
- Setup, run, TERM, KILL, and reap have separate monotonic budgets. Exhausting the run deadline does not consume the KILL/reap budget.
- On every write/read/framing/exit/identity failure, the owner closes the release/admission channels, revalidates identity, sends TERM then KILL only through retained authority, performs bounded nonblocking reap, and checks adopted/owned descendants.
- The outer process records/restores subreaper state where needed. Unexpected, escaped, identity-drifted, or unreaped descendants are terminal uncertainty.
- Success requires exact outer fd/child/descendant baselines and the actual production path baseline, independently of booleans returned by the inner launcher.

All primary and independently safe cleanup failures are retained in order. No `waitpid(..., 0)`, raw-PID signal, “close in a best-effort loop,” single exhausted deadline, or disposable-runner rationale is allowed.

## 8. Portable, non-native acceptance

Portable tests must invoke the real bootstrap dispatcher and real public owner state machines through primitive adapters. Source-text searches and completed-result mocks are non-accepting.

### 8.1 Bootstrap-mode matrix

For ordinary, mapping, and compression modes, tests must:

1. supply a synthetic retained source-root fd with the exact four source blobs and Git-tree identities;
2. drive `_bootstrap_with_ops` through authentication, exact synthetic-module load, admission installation, public-entry invocation, result validation, and canonical output;
3. prove exactly one expected public entry was called and no other public/private coordinator was reached;
4. remove the selected entry or its admission-consume edge and prove the row fails;
5. reject unknown/replayed mode, wrong result class, ordinary-result augmentation, mapping/compression cross-substitution, and extra/missing output fields; and
6. prove authority-bearing adapter events are absent before complete source admission.

Mutants cover wrong launcher/parser/closure/schema byte, wrong Git blob or revision, source/root generation drift, source-root replacement after held read, wrong root owner/mode/type, ambient `sys.path`/`PYTHONPATH`/cwd shadow, bytecode, nonempty environment, wrong Python object, fd 3/4 substitution, launcher held-fd substitution, and admission replay.

### 8.2 A production-owner matrix

Tests drive the actual `qualify_fixed_python_mapping` state machine with primitive cuts at source open/read, helper creation/pidfd/registration/release, maps read, each `map_files` open/read, second map read, TERM/KILL/reap, each close, and final baseline comparison. A real fixture includes executable, loader, and at least one library with provider closure. Missing loader, reordered role, duplicate `needed`, missing/duplicate provider, object oversize, map drift, digest drift, identity drift, helper EOF-live, close-after-effect, and residue reach their named production predicates.

Monkeypatching `_resolve_tool`, `_spawn_helper`, `_mapped_closure`, `_stop_helper`, or the complete owner to return success is forbidden.

### 8.3 B production-owner matrix

Tests drive the actual `launch_fixed_compression_qualification` path through closure preparation, issuance, both tools, final mappings, exact output comparison, and cleanup. Isolated mutants cover every one of the six seal bits, mask 15, source/sealed size or digest drift, each closure object/role/SONAME/needed/provider mutation, closure and mapping digest recomputation, wrong-but-equal outputs, one wrong output, tool reorder, mode substitution, and private metadata injection.

The positive oracle requires mask 63 and the fixed output digest above. Removing the fixed-byte comparison or any full-closure binding must make a sentinel fail.

### 8.4 Outer-owner matrix

A/B tests use a scripted process/fd adapter around the real outer state machine. They cut every allocation, fork/clone result, pidfd registration, pre-release identity observation, admission/release write, exec EOF, output/status read, identity revalidation, TERM, KILL, wait/reap, descendant census, and close before and after effect. Every case proves either exact restoration or an explicit terminal uncertainty; a fabricated pass result cannot satisfy cleanup.

No portable case invokes a real namespace, mount, seccomp, `map_files`, compression executable, sudo, native selector, or cloud operation.

## 9. Measured line disposition

Counts below are gross added physical lines from `bec0a19`, measured at the planning head. The exact recount is controlling; the final holistic report's `1889/1900` launcher statement is stale relative to the reviewed blob. The launcher is **1897/1900** at both `ea6e74f` and this planning head.

| Surface | Current | ADR 0090 high | Proposed disposition |
| --- | ---: | ---: | --- |
| closure owner | 2,098 | 2,100 | raise file high to 2,160 for the typed minimal A owner; trusted subtotal remains 8,930 |
| launcher | 1,897 | 1,900 | **no raise**; deletion/replacement plan below |
| launcher portable | 790 | 800 | delete completed mapping coordinator/static mode tests before adding real bootstrap matrices; remain <=800 |
| Job A driver | 300 | 300 | replace its 101-line raw launch region and delete unrelated namespace/root code; stop at 340 if readable owner cannot fit, requiring ADR 0091 to set 340 |
| Job B driver | 341 | 350 | replace its 103-line raw launch region and delete unrelated namespace/root code plus mask rewrite; stop at 390 if needed, requiring ADR 0091 to set 390 |
| native schema | 293 | 300 | reuse the closed object definition and replace mask 15 with 63; target <=300, stop before expansion beyond it |
| A focused test | 98 | 120 | delete token/regex acceptance and replace it with owner/fault tests; proposed high 170 |
| B focused test | 111 | 120 | delete token/regex acceptance and replace it with owner/fault tests; proposed high 170 |

The closure increase is measured from the missing ownership location: approximately 12 lines for a frozen result shape, 36 for the mapping-only owner transaction, 8 for admission/one-shot guards, and 6 lines of readable fault aggregation/margin. It is not code movement from the launcher; the launcher substitute is deleted, while the closure gains its own production owner. The independently binding trusted/portable subtotal and 13,000 aggregate remain unchanged because their current measured totals have sufficient room; no other file receives closure credit.

### Launcher 1,900 reconciliation

The launcher first removes these obsolete post-predecessor additions:

| Removed launcher region | Lines |
| --- | ---: |
| `_SourceAdmission._consume_mapping` substitute edge | 8 |
| `_MappingAuthority` and `_coordinate_admitted_mapping_only` | 54 |
| old `_runtime_metadata` executable-only side channel | 11 |
| ad-hoc `_execution_mapping_sha256` result mutation | 2 |
| **Total removed** | **75** |

This is removal of current added code, not offset credit for deleting predecessor code, renaming, moving code, or compressing lines. The resulting measured base is at most 1,822 gross lines. ADR 0091 allocates at most 78 replacement lines for:

- the bootstrap-installed one-shot admitted context and public-entry table;
- zero-argument public runtime/compression entries and closed result selection;
- complete B closure/tool metadata binding and fixed-output assertion; and
- readable mode/result validation and cleanup aggregation.

Therefore the launcher hard high remains **1,900**, with a mandatory stop at 1,900. If exact implementation measurement shows the replacement needs 79 or more lines after all 75 obsolete lines are actually absent, implementation stops and a revised measured ADR must justify a launcher raise; compression, semicolon packing, test relocation, or another private coordinator is not an alternative.

For the native slice, ADR 0091 should set A/B focused-test highs to 170 and, only if the deletion-first driver rewrites cross their old limits, A to 340 and B to 390. Set the independently binding native subtotal high to **4,250**; leave the 13,000 Outcome Two aggregate unchanged. Unused common/C/D/E/integration or trusted allowance is not transferable to an A/B file.

## 10. Sequencing and stop gates

1. Accept ADR 0091 with exact heads, public signatures, metadata formulas, source topology, and highs before changing implementation.
2. Delete the launcher substitute routes and static/completed portable acceptance first.
3. Add the closure-owned minimal A entry and its primitive-level portable matrix.
4. Add the launcher-owned B entry, exact metadata/output semantics, and real bootstrap-mode matrix.
5. Replace A/B outer launchers with bounded lease/process owners and their portable fault cuts.
6. Correct schema/goldens/common semantic checks, including mask 63 and digest recomputation.
7. Complete the separate common report-generation/baseline correction; A/B cannot publish authority without it.
8. Run ordinary portable/static gates only, then obtain fresh independent A/B, launcher/trust, common/schema, lifecycle, and holistic exact-head reviews.
9. Stop on any P0–P3, line-high excess, compressed authority flow, private-owner composition, dead sentinel, or unresolved common/C/D/E/integration dependency.
10. A later accepted ADR may identify a clean head and separately decide whether one native attempt is authorized.

## 11. Required outcome

A conforming correction makes the evidence statement narrow and truthful:

- A proves one real fixed Python mapping transaction owned by the admitted closure production API and nothing else.
- B proves the real fixed gzip/zstd production transaction, publishes all closure bindings, reports seals exactly as 63, and binds both outputs to the one fixed digest.
- A/B reach those owners through authenticated held source generations and an actual portable-tested mode dispatcher.
- Their outer process and descriptors are bounded, preregistered, one-shot, and independently residue-checked.

Anything weaker remains blocked and cannot be repaired by a native run.
