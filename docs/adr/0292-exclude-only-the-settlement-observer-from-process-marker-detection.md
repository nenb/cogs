# ADR 0292: Exclude only the settlement observer from process-marker detection

## Status

Accepted.

## Context

Protected-main reusable diagnostic run `33795829449`, attempt 1, passed both actual no-mint KVM routes. It also passed both cleanup-only recovery entries, including authenticated diagnostic control, publication custody, retired operation infrastructure, and immutable rollback. The subsequent fixed-root settlement failed at its process scan.

The scanner checks several lifecycle command markers, including `cogs-stage2-local-`. The settlement observer's own command is `stage2-local-settlement.py`, so the scanner classified its own live PID as an unsettled candidate before checking that PID's mount namespace, root, working directory, executable, and descriptors. This is an unavoidable observer identity, not lifecycle residue. Settlement, independent residue, and scaffolding restoration did not complete, so the run remains non-authorizing.

## Decision

For the real `/proc` inventory only, identify the scanner's exact current PID with `os.getpid()`. Suppress command-marker rejection only for that one observer generation. Continue performing every namespace, mount, root, cwd, executable, and descriptor check on it. Every other process, including a sibling with the same command marker, remains subject to marker rejection.

Add executable tests proving that a scanner whose own command contains the marker converges while a separate live process containing the same marker fails. Add a protected Linux/root tail test which creates isolated fixed roots, invokes the actual local cleanup and residue functions, and proves deletion plus independent residue. Run that test in the baseline Linux-foundation shard before any further KVM diagnostic.

## Consequences

The correction does not exempt a pathname, process family, parent, child, namespace, or arbitrary PID. It grants no lifecycle, receipt, publication, qualification, production, provider, or AWS authority. Run `33795829449` remains historical non-authorizing evidence. Another protected-main KVM diagnostic is permitted only after the complete no-KVM root tail and ordinary protected CI pass.
