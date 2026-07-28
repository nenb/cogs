# ADR 0091 production-operation API freeze

This is the W1 protocol checkpoint for W2–W5. It documents source contracts only and grants no native, sudo, workflow, cloud, or AWS execution authority.

## Common rules

All operations are fixed, one-shot, source-admitted operations. Production callables accept no `Ops`, path, argv, command, policy, fd number, PID, timeout, report, or cleanup claim. Private `*_with_ops` forms are portable-test seams only.

JSON is recursive `dataclasses.asdict`, then UTF-8 JSON with `sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`, and `allow_nan=False`, followed by exactly one LF. Tuples become JSON arrays. Unknown, missing, renamed, reordered typed fields, duplicate JSON keys, replay, or a result from another profile reject.

The ordinary `RuntimeQualificationResult` remains unchanged. Its exact fields are:

```text
version marker source_revision source_set_sha256 closure_sha256
 gzip_output_sha256 zstd_output_sha256
mapped_generations_exact user_namespace_exact pid_namespace_exact
mount_namespace_exact network_namespace_exact namespace_ownership_exact
namespace_handles_exact pid_one supplementary_groups_empty
effective_capabilities_zero permitted_capabilities_zero
inheritable_capabilities_zero bounding_capabilities_zero
ambient_capabilities_zero capabilities_zero noroot_locked no_new_privs
seccomp_installed seccomp_mode_exact seccomp_program_exact
seccomp_denials_exact exec_descriptor_consumed no_acquisition_route
root_readonly_noexec root_has_no_proc host_paths_absent checkout_absent
limits_exact descriptors_restored children_reaped descendants_reaped
mounts_restored paths_restored namespaces_released
namespace_handles_released
```

## Fixed admission profiles and owner entries

| Job | Admission version | Sole admitted production owner | Result version |
| --- | --- | --- | --- |
| A | `cogs.runtime-source-admission/mapping-v1` | `closure._qualify_admitted_fixed_python_mapping(admission)` | `cogs.runtime-mapping-qualification/v1` |
| B | `cogs.runtime-source-admission/compression-v1` | `launcher._launch_admitted_fixed_compression_qualification(admission, closure_module, ops)` | `cogs.runtime-compression-qualification/v1` |
| C | `cogs.runtime-source-admission/descriptor-v1` | `closure._qualify_admitted_fixed_descriptor_primitives(admission)` | `cogs.runtime-descriptor-qualification/v1` |
| D | `cogs.runtime-source-admission/lifecycle-v1` | `launcher._qualify_admitted_fixed_process_lifecycle(admission, ops)` | `cogs.runtime-lifecycle-qualification/v1` |
| E | `cogs.runtime-source-admission/sandbox-v1` | `launcher._launch_admitted_fixed_sandbox_qualification(admission, held_sources, ops)` | `cogs.sandbox-qualification/v1` |
| integration | `cogs.runtime-source-admission/v1` | `launcher._launch_admitted_fixed_runtime_qualification(admission, closure_module, ops)` | `cogs.runtime-qualification/v1` |

A uses `PreparedRuntimeClosure._for_fixed_mapping`; the deleted launcher `_MappingAuthority`/`_coordinate_admitted_mapping_only` route is not an API. C uses the closure's production `getdents64`/`close_range` adapter. D uses `_ProcessOwner` planned identity, credentialed pidfd transfer, stable census, signal, siginfo, and reap methods. E never loads the closure module or runs ELF/compression work.

## A client and result

Held-module production client:

```python
invoke_fixed_mapping_qualification(
    source_root_fd: int,
    revision: str,
    admitted_driver_fd: int,
) -> RuntimeMappingQualificationResult
```

Exact fields:

```text
version source_revision source_set_sha256 closure_sha256 mapping_sha256
objects mapped
mapped_generations_exact mapping_stable helper_reaped
descriptors_restored children_reaped
```

`objects` is executable, loader, then sorted libraries. Every row is exactly:

```text
role size_bytes sha256 soname needed
```

`needed` is ordered and unique. `mapped` has the same cardinality/order and each row is exactly `role sha256`. `closure_sha256` is recomputed from canonical full object rows; `mapping_sha256` is recomputed from canonical `[role, sha256]` rows.

## B client and result

Held-module production client:

```python
invoke_fixed_compression_qualification(
    source_root_fd: int,
    revision: str,
    admitted_driver_fd: int,
) -> RuntimeCompressionQualificationResult
```

Exact top-level fields:

```text
version source_revision source_set_sha256 closure_sha256 tools runtime
```

`tools` is exactly gzip then zstd. Each tool is exactly:

```text
id objects closure_sha256 mapping_sha256
source_sha256 source_size_bytes sealed_sha256 sealed_size_bytes seal_mask
execution_mapping_sha256 output_sha256
```

Each `objects` item is exactly `needed role sha256 size_bytes soname`, in executable/loader/sorted-library order. `seal_mask` is exactly `63`. Both output digests are exactly:

```text
6381d4535b13c7f030ca94bce250c1ec817c4aea8fa45c91e25c88995216f6b8
```

`runtime` is the exact unchanged ordinary result above. B adds nothing to that result.

## C and D clients

Held-module production clients:

```python
invoke_fixed_descriptor_qualification(
    source_root_fd: int,
    revision: str,
    admitted_driver_fd: int,
) -> DescriptorQualificationResult

invoke_fixed_lifecycle_qualification(
    source_root_fd: int,
    revision: str,
    admitted_driver_fd: int,
) -> LifecycleQualificationResult
```

Common exposes these only as the job-bound, zero-argument session conveniences `qualify_fixed_descriptor_primitives()` and `qualify_fixed_process_lifecycle()`. They share the same one-shot `run_fixed_operation` binding as the other profiles.

## C result

`DescriptorQualificationResult` fields are exactly:

```text
version source_revision source_set_sha256
nofile_measured nofile_normalized fd_198_exact fd_4096_exact
close_range_exact cloexec_exact inheritance_exact limit_restored
descriptors_restored children_reaped
```

## D result

`LifecycleQualificationResult` fields are exactly:

```text
version source_revision source_set_sha256
pdeathsig_armed parent_handshake_exact before_release_death
after_release_death starttime_revalidated session_owned
process_group_owned credentialed_pidfd_transfer stable_descendant_census
adoption_exact term_kill_bounded siginfo_exact all_reaped
subreaper_restored descriptors_restored
```

## E and integration session protocol

W2 exposes:

```python
session.run_fixed_operation("E") -> dict[str, primitive]
session.run_fixed_operation("integration") -> dict[str, primitive]
```

The held launcher must first return the exact frozen `SandboxQualificationResult` or `RuntimeQualificationResult`. Common accepts only that exact profile class (and each exact nested result class), then recursively converts it to the ordered, closed primitive dictionary consumed by all six drivers. A caller-created dataclass, mapping, ambient import, reordered field inventory, or cross-profile result is not conversion authority.

Its production-admission layer uses the W1 internal constructors:

```text
_admit_job_e_sandbox_with_held_sources
_admit_complete_runtime_with_held_sources
```

The returned one-shot invocation protocol has `result_type`, `source_revision`, `source_set_sha256`, and `invoke()`. `invoke()` accepts no argument and succeeds once only.

`SandboxQualificationResult` fields are exactly four strings plus 25 booleans:

```text
version source_revision source_set_sha256 seccomp_program_sha256
user_namespace_exact pid_namespace_exact mount_namespace_exact
network_namespace_exact namespace_ownership_exact pid_one capabilities_zero
noroot_locked no_new_privs seccomp_installed seccomp_mode_exact
seccomp_program_exact seccomp_denials_exact no_acquisition_route
root_readonly_noexec root_has_no_proc host_paths_absent checkout_absent
descriptors_restored children_reaped descendants_reaped mounts_restored
paths_restored namespaces_released namespace_handles_released
```

E's sudo envelope is exactly:

```text
/usr/bin/sudo -n --close-from=3 /usr/bin/env -i
/usr/bin/python3 -I -B -c <held-root-bootstrap>
```

The root bootstrap is at most 65,536 bytes. Before compiling/executing the held launcher it checks root/Python/argv/environment/fds, PDEATH and parent identity, canonical duplicate-free header, exact profile/version/keys/source path order/cardinality, per-source and aggregate sizes/digests, source-set and launcher bindings, and no trailing bytes. The stdin capsule is at most 8,000,000 bytes. Root receives no checkout pathname or checkout descriptor. Sandbox dispatch does not load/execute closure code.

Integration uses the same complete ordinary owner and returns only the unchanged ordinary result.

## Admission packet

The fd-3 canonical admission object is exactly:

```text
bootstrap_sha256 client_sha256 revision source_set_sha256 version
```

The selected fixed client path is authenticated from the operation table and exact Git revision. The process executes held launcher bytes; it does not re-execute a checkout launcher pathname. fd 4 is the retained source-root generation for unprivileged admission only. Root E receives neither fd 4 nor any checkout path.
