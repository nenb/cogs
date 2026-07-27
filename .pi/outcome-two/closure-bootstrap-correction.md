# Outcome 2 closure bootstrap and handoff correction design

- Design ID: `O2-BOOTSTRAP-DESIGN`
- Design-only head read: `2023e650e88767e0bd7574f0c302e780743eab5a`
- Implementation reviewed by the five closure reviews: `64c055762e260b8fc2eed96741bdb30c89183f3c`
- Accounting predecessor: `bec0a19b0b984f88ab9c2effc5059f3737915caa`
- Authorities read in full: ADR 0087, `OUTCOME-TWO-PLAN.md`, all five `closure-review-*.md` reports present at the design head, the three production modules, the closure schema, all seven portable Python suites, and their TypeScript wrapper.
- Disposition: correction design only. No production/schema/test/workflow edit and no production, native, workflow, namespace, mount, cloud, provider, or deployment execution is authorized by this document.

## 1. Exact implementation binding and decision

The production and schema blobs at `2023e65` are unchanged from the implementation reviewed at `64c0557`:

| Surface | Git blob | SHA-256 |
| --- | --- | --- |
| `completion_elf.py` | `5e3ba497a5862eb039b4b3a984e877c3dc470c9f` | `21f794d9175b4daa6526cba0df477ad31ea9b5d870576c1ffbc1761e7d1e7c5e` |
| `completion_trusted_runtime_closure.py` | `508378c42810729b43c300aea58d3ae3f1eda292` | `b0c4b1c8f466582e3638020ee6451ce68cb01e16f4e7d2ac1bde84fac0d61436` |
| `completion_trusted_runtime_launcher.py` | `0b00f02e0f45b5fc4850c85df56dfd4c819e2d1d` | `72a72b46bbf5b3b9948fe6c145d002080f49d726d7fc87478294a103cff7d556` |
| `trusted-runtime-closure-v1.json` | `cdd8abf68df367b4839511d34e0ffd8c0de1201a` | `8a57f0fe87191dc8bc295d06112f25478b4739eea96262f64bc6e20e33905610` |

The reviewed implementation must not be patched around its public handoff. The correction is architectural:

1. T0, not the code being admitted, is the trust root.
2. A small externally admitted bootstrap authenticates every transitive tracked source byte before importing any production module.
3. Production modules are loaded only from already-authenticated held bytes into a synthetic private package; the checkout is not an import root.
4. Raw descriptor handoff is removed from the public API. Issuance and consumption occur over a private OS capability channel wholly inside the admitted supervisor.
5. Every gzip/zstd execution object—not only each executable—is copied from its one held authenticated source descriptor into an exact sealed memfd generation.
6. The consumer independently binds those descriptor bytes and seals to the sealed canonical report before sandbox construction.
7. The actual final gzip/zstd process is exec-blocked behind T2; its complete executable mappings are validated twice by the trusted supervisor before the first input byte is written.
8. The kernel and production code never reopen an authenticated host runtime source for helper or final execution. Dynamic loading uses only sealed copies mounted into a private root.

This changes ADR 0087's exact public APIs and adds implementation surfaces while the parser and closure files are already at their non-transferable highs. A superseding ADR with new readable highs is required before implementation.

## 2. Trust root: no self-authentication claim

### 2.1 Controlling rule

A Python module cannot establish the trustworthiness of code that Python already parsed or executed. Neither `__file__`, `__spec__.origin`, a later pathname hash, a Python type name, nor a later Git query can retroactively authenticate import-time effects.

Therefore the production closure makes **no self-authentication claim**. The trust root is the externally reviewed T0 admission gate for one exact run and attempt. T0 must bind:

- exact same-repository source-head revision (never a merge SHA);
- separately reviewed workflow/envelope identities;
- the exact bootstrap blob SHA-256 and Git blob identity;
- the fixed implementation source-set digest described below; and
- a clean checkout/root descriptor whose revision and fixed blobs were checked before the bootstrap is executed.

A local caller may reproduce the protocol, but without that T0 binding its result has no native/evidence authority.

### 2.2 Why revision is external rather than embedded

The implementation must not hard-code its containing Git commit ID: changing a source file to contain that ID changes the commit ID and creates a circular identity. The revision is instead an immutable per-run T0 admission value. It is read once from a private inherited admission descriptor, compared to the external source-head value by T0, and never accepted from argv, the environment, the checkout's current `HEAD`, or a caller API.

The source digest is non-circular. It covers a fixed path set and exact bytes at the admitted revision. The bootstrap blob is separately authenticated by T0 before execution; the bootstrap does not claim to verify code that has already begun executing.

## 3. Exact pre-import bootstrap

### 3.1 New surface and invocation ABI

Add `deploy/aws-feasibility/remote/completion_trusted_runtime_bootstrap.py`. It is an executable bootstrap, not an importable library. It exposes no production symbol and accepts no argv or environment control.

T0 invokes the exact already-authenticated bootstrap bytes as:

```text
/usr/bin/env -i /usr/bin/python3 -I -B -
```

The fixed inherited descriptor ABI is:

| FD | Meaning |
| ---: | --- |
| 0 | exact authenticated bootstrap source stream; no workload input |
| 1 | bounded final canonical result only after complete cleanup |
| 2 | empty on success; one bounded categorical failure on safe failure |
| 3 | inherited read end containing one canonical `cogs.runtime-source-admission/v1` record and EOF |
| 4 | inherited `O_RDONLY|O_DIRECTORY` descriptor for the externally gated checkout root |

No other descriptor is admitted. Fds 3 and 4 are inheritable only for this one exec; bootstrap immediately sets both `CLOEXEC` and passes fd 4 explicitly only to the one fixed Git plumbing child. The T0 parent closes its write ends and all checkout/source descriptors immediately after spawn. The bootstrap reserves 0–4 before any open and rejects a nonempty environment, non-isolated Python, bytecode-enabled Python, non-Linux/non-x86-64 target, unexpected argv, or an unexpected baseline.

The admission record is exactly:

```json
{
  "bootstrap_sha256": "<64 lowercase hex externally checked by T0>",
  "revision": "<40 lowercase hex exact source head>",
  "source_set_sha256": "<64 lowercase hex>",
  "version": "cogs.runtime-source-admission/v1"
}
```

It is at most 512 bytes, strict canonical UTF-8 JSON, duplicate-key-free, integer-free, and exactly one LF. The bootstrap treats `bootstrap_sha256` only as a T0 assertion carried into the private admission state; it does not report that it authenticated itself.

### 3.2 Fixed transitive source set

The bootstrap contains this sole ordered path tuple; the admission record cannot add or remove a path:

```python
_FIXED_SOURCE_SET = (
    "deploy/aws-feasibility/remote/completion_elf.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_schema.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_closure.py",
    "deploy/aws-feasibility/remote/completion_trusted_runtime_launcher.py",
    "schemas/trusted-runtime-closure-v1.json",
)
```

`completion_trusted_runtime_schema.py` is a new standard-library-only, independent validator for the tracked schema. No production closure module imports any other tracked Python module. Standard-library files and `/usr/bin/python3` remain T0 host prerequisites; they are not promoted into repository-source claims.

For each fixed path, before production import, bootstrap:

1. walks from fd 4 component by component with no `realpath`, no `PATH`, no symlink following, no `..`, and fixed component/depth bounds;
2. opens the final component once with `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`;
3. requires a regular file, bounded size, and stable type/mode/UID/GID/device/inode/size/mtime/ctime around complete `pread` plus EOF;
4. retains the bytes in memory and does not reopen the source path;
5. obtains exactly one bounded `git ls-tree -rz --full-tree <admitted revision> -- <fixed paths>` result using fixed `/usr/bin/git`, fixed empty Git environment, fd-4 root via `/proc/self/fd/4`, and no hooks, aliases, replace objects, config, or caller arguments;
6. requires mode `100644`, type `blob`, exact fixed path order/cardinality, and recomputes each Git blob OID from the held bytes; and
7. computes the source-set digest below and byte-compares it to the admission record.

The source-set digest is unambiguous binary framing, not locale or JSON dependent:

```text
SHA256(
  for each path in _FIXED_SOURCE_SET:
    u32be(len(path_utf8)) || path_utf8 ||
    u64be(len(source_bytes)) || SHA256(source_bytes)
)
```

The admitted revision is independently bound by each tree blob OID; `source_set_sha256` binds the exact bytes and fixed order with SHA-256. A current `HEAD` lookup is forbidden.

### 3.3 Isolated module loading

Only after **all** source and schema bytes authenticate does bootstrap load code:

- create one synthetic package named from the digest, e.g. `_cogs_o2_<first 16 hex>`;
- give it `__path__=()` and no filesystem search location;
- pre-create only the four fixed private module objects;
- set each `__file__`/origin to a non-path URI `cogs-fixed:<digest>/<logical-name>`;
- compile directly from held bytes and execute in dependency order: ELF, schema validator, closure, launcher;
- use only relative imports within the synthetic package;
- never add the checkout, current directory, remote directory, or an empty string to `sys.path`;
- reject any tracked import request outside the four-module set; and
- close all source descriptors before calling authority-bearing preparation.

The schema JSON is retained as authenticated bytes and passed privately to the independent validator. Production does not reopen `schemas/trusted-runtime-closure-v1.json`.

`SourceAdmission` is a private frozen value containing only `revision`, `bootstrap_sha256`, and `source_set_sha256`. It is constructed by bootstrap after the transitions above and passed directly to the private coordinator. No public function accepts or constructs it.

### 3.4 Bootstrap state machine

```text
NEW
  -> ADMISSION_READ
  -> SOURCES_HELD
  -> SOURCES_AUTHENTICATED
  -> MODULES_LOADED
  -> RUNNING
  -> RESULT_VALIDATED
  -> CLOSED

Any state before CLOSED -> POISONED -> CLOSED only after every owned fd/child is
proved recovered. An uncertain close/reap repeats the same terminal error.
```

No transition to `MODULES_LOADED` is possible until the fixed revision, every Git blob, every SHA-256, and the aggregate source digest agree. No transition to `RUNNING` is possible while a checkout source fd remains open.

## 4. Corrected internal APIs

### 4.1 Remove the public handoff API

Delete these production APIs rather than trying to make a Python dataclass nominally private:

```python
RuntimeClosureHandoff(...)
PreparedRuntimeClosure.settle_fixed_handoff()
prepare_fixed_runtime_closure()
launch_fixed_runtime_qualification(handoff)
launch_fixed_sandbox_probe()
```

A same-process Python object is forgeable through constructors, attribute mutation, monkey-patching, fd close/reuse, or private-name access. The admitted process must load no untrusted module and must never return authority-bearing fds to its caller.

### 4.2 Exact replacement API shape

The only external production entry is the zero-argument bootstrap executable and its fixed fd ABI. Inside the authenticated synthetic package, use these private interfaces:

```python
# completion_trusted_runtime_closure.py
class PreparedRuntimeClosure:
    @property
    def canonical_report(self) -> bytes: ...       # READY only
    def _issue_once(self, issuer: "_PrivateIssuer") -> None: ...
    def close(self) -> None: ...


def _prepare_admitted_fixed_runtime_closure(
    admission: "_SourceAdmission",
    issuer: "_PrivateIssuer",
) -> PreparedRuntimeClosure: ...

# completion_trusted_runtime_launcher.py
def _run_admitted_fixed_runtime_qualification(
    admission: "_SourceAdmission",
    schema_bytes: bytes,
) -> RuntimeQualificationResult: ...
```

`_run_admitted_fixed_runtime_qualification` creates the issuer, closure owner, private channel, sandbox owners, and outer recovery supervisor itself. It accepts no handoff, path, fd, argv, environment, role, input, mount, namespace, seccomp, timeout, or policy argument. Test adapters remain module-private and are loaded only by portable tests, never by bootstrap.

The result adds `source_set_sha256` beside `source_revision`; it carries no fd and is finalized only after all descriptor, child, mount, path, namespace, rlimit, and checkout/source baselines are restored.

## 5. Private unforgeable issuer/consumer protocol

### 5.1 Capability channel

`_PrivateIssuer` creates a Linux `AF_UNIX` `SOCK_SEQPACKET|SOCK_CLOEXEC` socketpair and a 256-bit `getrandom` nonce before forking the fixed consumer. The endpoints are registered before fork and `SO_PASSCRED` is enabled for the one packet. The parent retains only the issuer endpoint; the fixed child retains only the consumer endpoint. Neither endpoint nor nonce is returned, exported, placed in the report, or inherited by any workload.

Issuance is exactly one `sendmsg` record containing:

- protocol literal `cogs.runtime-handoff/v1`;
- the nonce;
- admitted revision and source-set SHA-256;
- SHA-256 of the exact canonical report bytes including terminal LF;
- top-level report `closure_sha256`;
- canonical fixed descriptor-binding rows; and
- one `SCM_RIGHTS` array containing the report and the deduplicated sealed object descriptors.

The consumer uses `recvmsg(..., MSG_CMSG_CLOEXEC)` once and requires:

- exact packet length and canonical decoding;
- no truncation flags, unknown ancillary record, second packet, EOF-before-record, or extra fd;
- exact sender credentials/expected supervisor PID and nonce;
- exact fd cardinality and binding-row cardinality;
- distinct received fd numbers; and
- the admitted revision/source digest inherited from bootstrap.

The socket endpoint is the issuer capability. An outside caller cannot construct a handoff because it has neither endpoint nor nonce, and no API accepts raw fds. A forged Python class or `SimpleNamespace` is irrelevant. Closing/reusing an fd before `sendmsg` changes issuer revalidation and fails; substitution after `SCM_RIGHTS` is impossible because the consumer owns a distinct received reference and verifies it independently.

### 5.2 Binding rows

A binding row is exactly:

```text
(tool_index, object_index, role, descriptor_index, size, sha256,
 seal_profile="linux-memfd-exec-seals-v1")
```

Rows cover every gzip and zstd report object in report order: executable, loader, then sorted libraries. If the same sealed object is intentionally shared, multiple rows may name one descriptor index only when `(size, sha256, ELF metadata)` are byte-identical. Any undeclared alias, duplicate role identity, conflicting SONAME provider, or descriptor with no row is terminal.

The binding-table digest is SHA-256 of canonical JSON bytes for the rows without LF. It is private handoff protocol state, not a new public report field. The report already binds each row's role/order/size/SHA-256 through each tool `closure_sha256` and the top-level digest; the fixed protocol binds the required seal profile.

### 5.3 Descriptor and report verification before sandboxing

Issuer and consumer independently perform all of the following on their own fd references:

1. report: regular, bounded exact size, `O_RDONLY`, `CLOEXEC`, exact `_DATA_SEALS`, complete `pread` plus EOF, exact report SHA-256;
2. each execution object: regular, mode `0555`, bounded exact size, `CLOEXEC`, exact `_EXEC_SEALS`, complete `pread` plus EOF, exact SHA-256, strict ELF parse;
3. report: strict canonical decoder, independent tracked-schema validator, and separate semantic validator/re-encoder;
4. binding: exact tool/object order, role, size, digest, SONAME, ordered `DT_NEEDED`, loader/interpreter relationship, provider uniqueness, and binding-table digest; and
5. identity: stable fstat/seal profile around every complete read and no unexpected descriptor alias.

Only after both sides produce the same report SHA-256, closure SHA-256, binding-table SHA-256, and descriptor identities may issuer state become `CLAIMED`.

## 6. No source reopen and exact execution generations

### 6.1 One-open rule

For every Python/gzip/zstd executable, loader, and library:

- component walking opens the final host runtime object exactly once;
- complete authentication and all copies use that held fd;
- path stability is rechecked with retained directory authority and no-follow `stat` observations, not by reopening the final object;
- no `realpath`, `Path.resolve`, current-path source hash, or later host pathname open is permitted; and
- after sealed-copy verification and report construction, every host source fd closes before `READY`.

The reviewed `_authenticate` second traversal may remain only as a no-follow component/final-entry observation. It must not return or open a second final fd. Close errors are aggregated without retrying a descriptor whose ownership became uncertain.

### 6.2 Seal the complete execution closure

Replace executable-only sealing with `_seal_object` for every object in all three tool closures. It copies directly from `AuthenticatedObject.held_fd`, checks source generation before and after, sets mode `0555`, fsyncs, performs complete same-fd readback, reparses ELF, compares size/SHA-256/metadata, and requires exact `_EXEC_SEALS`.

- Python's sealed copies are preparation-only and close after its fixed helper mapping proof.
- gzip/zstd sealed copies survive into the private issuer bundle.
- Shared authenticated identities are copied once and represented by the exact declared binding aliases.
- No source pathname is opened by sealing, helper execution, final execution, or cleanup.

### 6.3 Private immutable loader roots

For each tool helper/final process, trusted setup creates a dedicated mount namespace and a private tmpfs root. It creates only fixed directories and fixed target names, then bind-mounts `/proc/self/fd/<sealed-copy-fd>` to those targets. These are sealed-copy fds, never host source fds. The loader is mounted at the fixed interpreter path; each provider is mounted under the fixed private library root by its validated SONAME. Every bind and the root are remounted read-only before chroot. Setup procfs is removed before T2 unless the fixed workload contract independently requires it.

The child then closes all bundle/setup fds except the fixed executable/report/data descriptors, enters chroot and final user/PID/mount/network namespaces, clears groups and every capability set, locks securebits `noroot`, sets NNP, installs the fixed seccomp policy, and `execveat`s the sealed executable. Consequently the kernel resolves PT_INTERP and `DT_NEEDED` only from sealed copies. Host loader/library paths are never reopened after authentication.

## 7. Final exec mapping validation before input

For gzip and zstd independently, use this exact order:

```text
consumer descriptor/report verification
-> private immutable root complete
-> child identity registered (pidfd, start time, SID, PGID, executable identity)
-> child boundary setup
-> execveat sealed executable
-> CLOEXEC status pipe reaches clean EOF (exec complete)
-> child/descendant identity revalidated
-> complete maps snapshot A to EOF (4 MiB / 4,096 lines)
-> open/hash/parse every executable nonzero-inode mapping via map_files
-> compare exact unique mapped objects to this tool's descriptor bindings and report
-> permit only [vdso] and [vsyscall] zero-inode executable mappings
-> complete maps snapshot B to EOF
-> require A == B
-> recompute [role, sha256] mapping digest and require report mapping_sha256
-> revalidate child identity, no descendants, sandbox facts, and unopened input gate
-> write the first fixed compressed input byte
```

The input pipe is created empty and retained only by the trusted supervisor until the final arrow. No bootstrap, caller, report, setup child, or workload can write it earlier. Any status byte, timeout, maps drift, unknown/ambiguous mapping, missing object, descriptor/report mismatch, boundary mismatch, descendant, or cleanup uncertainty closes the input gate without writing and enters abort cleanup.

Mapping validation is against the final exec, not only a preparation helper. The trusted outer supervisor may read host procfs; the T2 workload receives no procfs discovery authority. After release, fixed output is bounded, direct child/descendant identity remains supervised, and wait/reap uses pidfd plus start-time/SID/PGID identity and fixed TERM/KILL deadlines.

## 8. Report validation and sealing

The canonical report shape need not expose source revision, source digest, fd numbers, private binding rows, mount names, or generations. Its existing object size/digest/order records are sufficient for descriptor binding.

Production report issuance must use three independent operations:

1. closure semantic codec builds and validates the value;
2. authenticated `completion_trusted_runtime_schema.py` validates the exact value against the authenticated tracked schema bytes; and
3. launcher consumer independently decodes, semantically validates, and re-encodes byte-identically.

The report is encoded twice from independently reconstructed values and compared before sealing. Its memfd is sealed once. On close failure, ownership becomes uncertain and the number is never retried. A read-only duplicate is created before sealing/close settlement or transferred through `SCM_RIGHTS` with access-mode verification; no `/proc/self/fd` reopen is required after a close attempt.

The schema must also be tightened so its executable/loader `contains` branches require the `role` property, object order/cardinality semantics agree with both codecs, library SONAME is mandatory, and all SONAME/needed limits agree. Schema validation is not replaced by selected source-text assertions.

## 9. State transitions and failure ownership

### 9.1 Closure owner

```text
NEW -> PREPARING -> READY -> ISSUING -> CONSUMING -> CONSUMED -> CLOSED
                 \-> POISONED -------------------------------> CLOSED only after proved recovery
```

- `READY`: source fds and preparation helpers are gone; report and exact sealed bundle only.
- `ISSUING`: one private packet is being formed; all fds remain issuer-owned until successful `sendmsg` and exact consumer claim.
- `CONSUMING`: consumer owns received references while issuer retains recovery references.
- `CONSUMED`: both tools completed, all children reaped, mounts/namespaces removed, and consumer references closed; issuer may close recovery references.
- no public settlement and no second issue.

### 9.2 Private consumer

```text
EMPTY -> CLAIMED -> VERIFIED -> SANDBOX_READY -> EXEC_BLOCKED
      -> MAPPINGS_VERIFIED -> INPUT_RELEASED -> COMPLETE -> CLOSED

Any state -> ABORTING -> CLOSED, or POISONED if exact cleanup cannot be proved.
```

`INPUT_RELEASED` is irreversible and is reachable only from `MAPPINGS_VERIFIED`. A report/result is not finalized before `COMPLETE` cleanup.

### 9.3 Crash owner

The bootstrap process is the fixed outer supervisor. It registers consumer pidfd/start-time/SID/PGID and channel endpoints before release. Parent-death cuts use a real child and PDEATHSIG, but recovery still revalidates and reaps the child. Anonymous descriptors close with process death; named tmpfs/mount state is owned through retained namespace/mount/root descriptors. A fresh supervisor process may recover only retained exact authority supplied by the fixed outer launcher; an unrelated fresh success is never called recovery. Inability to prove identity or cleanup is a terminal uncertain result.

## 10. Exact HEAD line ranges to replace

Line numbers below refer to the exact `2023e65` files bound in section 1. They are replacement boundaries for the future implementation, not edits made by this design.

### Production and schema

| Surface and exact current range | Required replacement |
| --- | --- |
| **new** `completion_trusted_runtime_bootstrap.py` | Implement sections 2–3 and call only the private admitted coordinator. |
| **new** `completion_trusted_runtime_schema.py` | Independent authenticated tracked-schema validator; no closure codec import. |
| `completion_elf.py:117-153` | Replace PT_LOAD alignment/overlap/mapping model with fixed x86-64 page-congruent, page-rounded semantics including BSS and remap-order rejection. |
| `completion_trusted_runtime_closure.py:8-20` | Use private synthetic-package relative imports; remove ambient `completion_elf` import. |
| `completion_trusted_runtime_closure.py:79-83` | Delete public `RuntimeClosureHandoff`; add private binding/sealed-object records. |
| `completion_trusted_runtime_closure.py:150-168` | Replace owner states/cuts with `ISSUING`, `CONSUMING`, `CONSUMED` and no public handoff cuts. |
| `completion_trusted_runtime_closure.py:158-254` | Extend private ops for exact fd-directory enumeration, `close_range`, socketpair/SCM_RIGHTS, sealed-copy mount authority, and bounded process identity. Replace `listdir("/proc/self/fd")` at 241–245 with an explicitly opened directory fd excluded from its own result. |
| `completion_trusted_runtime_closure.py:317-443` | Replace resolver/authentication with retained component authority and one final-object open; no second final open or realpath. |
| `completion_trusted_runtime_closure.py:581-797` | Replace proc/helper lifecycle and mapping path with register-before-fork, fixed stdio reservation, exact inherited-fd allowlist, bounded identity-safe reap, primary-plus-close aggregation, sealed-root execution, and reusable final mapping verifier. |
| `completion_trusted_runtime_closure.py:798-834` | Generalize executable-only `_seal_source` to deduplicated `_seal_object` for every closure object. |
| `completion_trusted_runtime_closure.py:836-862` | Replace report sealing to avoid uncertain-fd retry and post-close `/proc/self/fd` reopen. |
| `completion_trusted_runtime_closure.py:864-1026` | Split producer semantic codec from independent tracked-schema validation and true independent re-encoding. |
| `completion_trusted_runtime_closure.py:1028-1220` | Replace public settlement/constructor/export with private admitted prepare, one-shot issuer, complete sealed bundle, corrected close publication order, source-close-before-READY, and exact states in section 9. |
| `completion_trusted_runtime_launcher.py:1-46` | Remove pathname/Git/source-self-auth constants and imports; accept only private admitted state from bootstrap. |
| `completion_trusted_runtime_launcher.py:64-88` | Add `source_set_sha256` and cleanup facts derived from owned operations, not constants. |
| `completion_trusted_runtime_launcher.py:96-249` | Replace scripted/system post-import authentication adapters and pathname source reopen with private issuer/consumer, descriptor/report binding, exact baseline, and admitted source identity. |
| `completion_trusted_runtime_launcher.py:254-350` | Keep an independently implemented consumer codec, align it exactly with tightened schema, and consume authenticated schema bytes without pathname reopen. |
| `completion_trusted_runtime_launcher.py:352-485` | Delete raw handoff extraction and ambient tool execution; implement private packet claim, immutable-root T2 construction, identity-safe child supervision, final mapping validation, and input gate order. |
| `completion_trusted_runtime_launcher.py:487-520` | Delete inspection-only sandbox probe; implement the actual fixed sandbox owner/checks used by both integration and Job E. |
| `completion_trusted_runtime_launcher.py:523-599` | Delete public handoff/sandbox entry points and replace with the sole private admitted coordinator and cleanup/result finalization. |
| `schemas/trusted-runtime-closure-v1.json:30-112` | Tighten role/cardinality/order/SONAME semantics and make schema/producer/consumer constraints identical; retain closed metadata-only shape. |

Replacing broad ranges is intentional. Keeping current public constructors or current ambient process execution would preserve the P0 defects even if digest checks were added nearby.

### Portable tests and fixtures

| Surface and exact current range | Required replacement/extension |
| --- | --- |
| `test/outcome-two-runtime-closure-portable.py:18-23` | Load authenticated in-memory modules through a test-only bootstrap harness; do not make `sys.path` an authority model. |
| `test/outcome-two-runtime-closure-portable.py:39-58` | Port the full prior hostile ELF matrix plus page alias/alignment/BSS/remap cases to `parse_elf64`. |
| `test/outcome-two-runtime-closure-portable.py:61-165` | Model symlink chains, absolute/`..` targets, ancestor/final replacement, every read phase, same-identity alias, distinct ambiguity, and consume every fixture row (remove `cases[:10]`). |
| `test/outcome-two-runtime-closure-portable.py:175-189` | Add true deduplicated three-tool aggregate and cross-tool duplicate-role identity cases. |
| `test/outcome-two-mapped-closure-portable.py:50-167` | Consume every hostile maps fixture, ambiguous fingerprint and 129-object rows; add primary-plus-map-close and final-exec mapping-before-input order. |
| `test/outcome-two-sealing-portable.py:34-154` | Extend matrix to every closure object, report sealing, uncertain close/no retry, binding-table mutation, and source-open sentinel. |
| `test/outcome-two-lifecycle-portable.py:34-266` | Model live/reaped state independently of pidfd, closed stdio permutations, arbitrary inherited fds, production fd enumeration, identity drift, bounded wait-after-EOF, descendants, mounts/namespaces, and all declared cleanup rows. |
| `test/outcome-two-recovery-portable.py:16-29` | Replace pathname `spec_from_file_location` with the bootstrap test harness. |
| `test/outcome-two-recovery-portable.py:31-235` | Drive real outer-supervisor/channel/child authority through crash cuts; an unrelated fresh success is not recovery. Correct `cleanup.after` so uncertain completion stays the same poison. |
| `test/outcome-two-runtime-report-portable.py:16-27` | Use held authenticated schema/module bytes. |
| `test/outcome-two-runtime-report-portable.py:50-139` | Recompute dependent digests for each semantic mutation and drive golden/hostile values independently through schema, producer codec, consumer codec, and report-seal faults. |
| `test/outcome-two-trusted-launcher-portable.py:15-25` | Replace direct pathname import with bootstrap harness. |
| `test/outcome-two-trusted-launcher-portable.py:28-140` | Replace fabricated `SimpleNamespace` handoff/results with socket/SCM_RIGHTS, fd substitution/reuse, report/executable/library mismatch, mount/sandbox, mapping-before-input, process deadline, descendant, and cleanup state adapters. |
| `test/outcome-two-portable.test.ts:6-45` | Invoke the corrected suites with fixed `/usr/bin/python3`, empty fixed environment, no ambient `PATH`, and include bootstrap/schema-validator suites. |
| `test/fixtures/outcome-two/**` | Enforce one-to-one fixture truth: every manifest row selected exactly once; add bootstrap admission, source race, descriptor binding, final mapping, sandbox, and crash-owner transcripts. |

## 11. Review-finding resolution matrix

| Review blocker | Design resolution |
| --- | --- |
| Post-effect/self source authentication | Sections 2–3: T0 is explicit trust root; every transitive source byte authenticates before production import/effect. |
| Ambient/isolated module loading | Section 3.3: held-byte synthetic package, relative fixed imports, no checkout import path. |
| Forgeable public dataclass/raw fd handoff | Sections 4–5: no public handoff; private one-shot OS capability channel and consumer-owned received refs. |
| Executable unrelated to report | Section 5.3: full byte/size/ELF/seal/report binding independently on issuer and consumer. |
| Loader/library generation drift at final exec | Sections 6–7: complete closure sealed and mounted from sealed fds; final maps checked before input. |
| Host source reopened after authentication | Section 6: one final host open; all helpers and final exec use sealed copies only. |
| Ambient helper fds/closed stdio | Sections 6–7 and test map: reserve stdio and close exact complement before exec. |
| No actual T2 launcher | Sections 6.3–7: production owner creates the boundary; probe reuses it rather than inspecting a caller. |
| Report schema not independently applied | Section 8: separate authenticated schema validator and consumer codec. |
| Report close fd-reuse hazard | Section 8: no retry after uncertain close and no post-close reopen. |
| Final wait/reap and descendants unbounded | Sections 7 and 9: pidfd/start-time/SID/PGID, deadlines, descendants, outer owner. |
| False crash recovery | Section 9.3: real retained authority and recovery; fresh retry is not recovery. |
| Real fd baseline enumeration defect | Production replacement table: explicit directory fd omitted from snapshot. |
| Parser page model | Parser replacement range and hostile matrix. |
| Dead fixtures/mocked security boundary | Portable replacement table requires fixture truth and direct protocol/state adapters. |

## 12. Implementation gate

Before any implementation:

1. accept a superseding ADR authorizing the two new production files, revised APIs/trust boundary, complete sealed closure bundle, and readable per-file highs;
2. assign the externally admitted bootstrap/T0 gate to a reviewed tracked native driver or workflow gate without moving security logic into YAML;
3. implement portable bootstrap/source/handoff/report/lifecycle matrices before native execution;
4. obtain a new exact-head hostile review with no unresolved P0–P3; and only then
5. run native A–E, followed by thin integration on the same exact clean head and attempt.

This design grants no permission to preserve the current public handoff for compatibility, to infer provenance from a Python type, to treat current `HEAD` as the source revision, to reopen a host runtime path after authentication, to release input before final mappings settle, or to let Job E/workflow code substitute for the production sandbox owner.

O2-BOOTSTRAP-DESIGN COMPLETE
