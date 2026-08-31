# ADR 0262: Accept consumed report proof and replace qualification

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-31

Exact stable-QEMU diagnostic run `33358075775`, attempt 1, completed the full real lifecycle, minted the package-private receipt, immediately consumed it, and derived canonical report bytes of size 8,512 with SHA-256 `1a3479112343e2f4f4fb9318a3a4d645eeedad4a1571dcfc6517805eee77e44e`. It wrote and uploaded no report. Recovery and exact scaffolding cleanup passed. The diagnostic proves the corrected terminal derivation path but grants no qualification or promotion claim.

Bind failed formal run `33350122895`, attempt 1, H `1fc2dea2dcefea2aaf71a80356e0f5ed946e9991`, control head `9a525719bed23e3a948f760862722e8e4864a575`, exact title, and failed conclusion as the fifteenth non-authorizing predecessor. That run's lifecycle and cleanup passed but it produced no artifact.

After this workflow correction merges on protected `main`, update the control variable to that merge and authorize exactly one attempt-1 formal replacement qualification with unchanged H and staged static package. All report schema/semantic validation, exact artifact-ID readback, separate upload receipt, teardown, and zero-residue requirements remain mandatory. Raise only the complete tracked-source cardinality bound from 1,223 to exactly 1,224 files and retain all other bounds.

This grants no AWS, provider, deployment, campaign, production, release, retry, or promotion operation.
