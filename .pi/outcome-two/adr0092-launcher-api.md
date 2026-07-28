# ADR 0092 launcher API note

This note freezes the corrected launcher handoff for the common owner. It grants no native, sudo, workflow, provider, cloud, or AWS execution authority.

## Authenticated caller entry

Common independently holds and authenticates the four `_FIXED_SOURCE_SET` generations and the job client against the exact Git head **before compiling launcher bytes**. It then calls exactly:

```python
invoke_fixed_admitted_operation(
    operation: str,                    # A, B, C, D, E, or integration
    head_sha: str,                     # exact 40-byte lowercase Git SHA
    held_sources: types.MappingProxyType,  # exactly four fixed path -> bytes rows
    held_client_bytes: bytes,
    source_set_digest: str,
) -> exact fixed result type
```

The launcher rechecks exact source cardinality/types and `source_set_digest`, binds the fixed operation to its one exact result type, creates a sealed held-source transport, and never opens a checkout source or client pathname. The inner bootstrap authenticates that sealed transport before compiling its held launcher generation. Result revision/source-set identity is checked after the one-shot operation.

The exact operation/result mapping remains:

- A -> `RuntimeMappingQualificationResult`
- B -> `RuntimeCompressionQualificationResult`
- C -> `DescriptorQualificationResult`
- D -> `LifecycleQualificationResult`
- E -> `SandboxQualificationResult`
- integration -> unchanged `RuntimeQualificationResult`

B now contains the closed `parser` field between `closure_sha256` and `tools`. Its exact shape is `RuntimeCompressionParserObservation(closure_sha256, objects)`. This lets common reconstruct the aggregate parser/zstd/gzip closure summary without changing the ordinary runtime result.

## Root authority

E derives `_RootCapsuleAuthority` only from the already admitted held generations. `_render_root_bootstrap()` embeds its canonical exact revision, launcher SHA-256, source-set SHA-256, and ordered per-source size/digest rows into the fixed sudo command. Root compares every independently embedded value with the capsule before `compile` or `exec`. A self-consistent capsule with different launcher/source bytes therefore rejects with `root-authority` before supplied Python executes.

The rendered command, including its embedded authority, is the command identity that a later execution ADR/sudo policy must pin exactly. Root receives only fds 0-2 and opens no checkout pathname or descriptor.

## Process and sandbox ownership

D executes three independent production transactions: before-release PDEATH, after-release PDEATH, and TERM-then-KILL. Each uses a parent-confirmed post-`setsid` second gate, deadline-driven credentialed one-pidfd transfer with case/role/full identity and EOF replay closure, stable identity-edge census, stable adoption, exact siginfo/wait/reap, and aggregate subreaper/fd/process settlement.

E creates the PID-namespace inner process through the process owner, transfers and registers its pidfd before release, retains all-path settlement, and performs outer `/proc/<pid>` root/mount readback only after the inner process has chrooted and reported its boundary.

## Working-tree content hashes

These hashes identify the launcher bytes frozen by this note before commit metadata is added:

- launcher SHA-256: `9291ca06ba4d5721b35a1c1c950cfd3d33d93b34e740760684f7bd018d3b97ec`
- launcher Git-blob SHA-1: `2114d47ec917582c6e47e2e9696e28602efb1442`
- four-source framed SHA-256: `25aeb9d764dbe12dec330d408ddccd9f75fba986cd02b4ce132c6c6b7b016447`
- root-bootstrap template SHA-256: `73434c215c43d9806129961246933237a197d1c2455355e098965bebd5af09f2`

The per-run rendered root-bootstrap hash additionally binds the exact accepted head and source generations and must be recorded by the later execution authority. The template hash alone is not sudo authority.
