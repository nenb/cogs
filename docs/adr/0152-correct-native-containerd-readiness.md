# ADR 0152: Correct native containerd readiness

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

A private no-KVM execution on `osito` proved that the pinned containerd 2.2.1 starts at the fixed short endpoint `/run/c42d/s`. It also exposed two exact integration facts absent from synthetic tests: pinned `ctr` emits fixed-width list headers with trailing spaces and containerd creates a distinct companion listener at `/run/c42d/s.ttrpc`. Treating the first header as malformed blocks readiness; ignoring the second listener leaves live or stale mutable state outside ownership and cleanup.

Accept only bounded printable-ASCII table output with the exact ordered header fields, while admitting native trailing spaces and rejecting tabs, encoding drift, extra fields, malformed rows, duplicates, or unbounded output. Own both short Unix listeners as separate root-owned generations correlated to descriptors held by the exact retained containerd PID. Bind both into durable daemon/readiness state. Prevalidate both before mutation, quarantine and unlink by retained identity, fsync the parent, prove link-count settlement, and require all active/quarantine names absent. Replacement or uncertainty preserves state and fails closed.

The successful private readiness record is diagnostic only and grants no qualification claim. No AWS, promotion, production, or release authority follows.
