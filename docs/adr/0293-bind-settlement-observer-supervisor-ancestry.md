# ADR 0293: Bind settlement observer supervisor ancestry

## Status

Accepted.

## Context

Protected-main reusable diagnostic run `33814058885`, attempt 1, passed both actual no-mint routes and both cleanup-only recovery entries. Settlement still failed at its process scan after ADR 0292 excluded the observer's own PID.

The workflow launches settlement through `sudo env`. That live supervisor carries run-unique `REPORT_STAGING`, `REPORT_READBACK_STAGING`, and `RECEIPT_READBACK_STAGING` arguments containing the broad `cogs-stage2-local-` marker. It is an unavoidable ancestor waiting for the observer, not lifecycle residue. ADR 0292 covered only the child observer and therefore did not cover the real invocation shape. Settlement, residue, and scaffolding restoration did not complete; the run remains non-authorizing.

## Decision

For real `/proc` only, derive the observer's exact current process ancestry from each PID's stat record. Bind every ancestry member by PID plus start time, cap traversal at 64 generations, and fail closed on missing, malformed, or non-terminating ancestry. Suppress command-marker rejection only for those exact live generations. Continue all mount-namespace, mount, root, cwd, executable, and descriptor checks for every ancestor.

A sibling or unrelated process carrying the same marker remains rejected. Synthetic proc inventories receive no ancestry exemption. Extend the protected Linux/root tail invocation so its actual `sudo env` supervisor carries the same three run-unique staging arguments as the diagnostic workflow; require cleanup and residue to pass while a separately spawned sibling-marker process is still rejected.

## Consequences

This is not a process-name, UID, namespace, parent-family, or pathname exemption. PID reuse cannot inherit it because start time is part of the bound generation. No lifecycle, receipt, publication, qualification, provider, or AWS authority is added. Run `33814058885` remains historical non-authorizing evidence. Another KVM diagnostic remains blocked until the corrected root tail and protected CI pass.
