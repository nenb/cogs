# ADR 0258: Bind terminal runtime to stable QEMU identity

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-31

Bounded trace diagnostic run `33339461389`, attempt 1, identified the exact terminal invariant: `completion_local_evidence.py:841` compared `runtime.qemu_process_sha256` with `OWNERSHIP_OBSERVED.proof_sha256`. Exact recovery and scaffolding cleanup passed; no receipt or report was minted.

Those digests intentionally describe different snapshots. The runtime owner digest covers a complete runtime observation after later journal progress, including that observation's current terminal journal hash. The durable ownership proof covers the earlier ownership observation before its settlement append. Comparing them requires mutable journal state to remain unchanged and therefore rejects the valid real lifecycle.

Keep the ownership record mandatory, but replace the stale aggregate-digest comparison with exact stable identity binding. Require platform and causal runtime owner results to agree on QEMU argv, PID, start time, executable device/inode, observer QMP socket, KVM device/inode/rdev/API, and QMP presence/enabled state. Independently require the authenticated durable `RUNTIME_ROLE_IDENTITIES_V1` QEMU row to match the runtime PID, start time, and executable device/inode. Shim, virtiofsd, namespaces, executable generations, role absence, ownership proof, ordered teardown, and runtime attestation remain separately required. Apply the same stable check to canonical certain-failure reports when causal runtime evidence exists.

Add hostile tests for changed platform identity and changed durable QEMU identity, and explicitly prove that changing journal-bound aggregate observation hashes does not masquerade as process replacement. The prior H remains preserved history; this correction requires a newly reviewed H, independently produced G, and one fresh formal qualification. Raise only the complete tracked-source cardinality bound from 1,219 to exactly 1,220 files and retain all other bounds.

This grants no AWS, provider, deployment, campaign, production, release, retry, or promotion operation.
