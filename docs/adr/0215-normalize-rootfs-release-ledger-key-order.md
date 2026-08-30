# ADR 0215: Normalize rootfs-release ledger key order

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H59 completed the entire input-removal transition, appended `INPUT_REMOVED`, and prepared `ROOTFS_RELEASE_READY`. Rootfs release authorization then passed the operation journal's canonical `rootfs_ledger_key` dictionary directly to the rootfs ledger. The operation codec had canonicalized nested keys alphabetically, while the ledger's typed host-key parser requires its reviewed field order: `mount_id`, `device`, `inode`, `kind`.

Before constructing the `release-authorized` ledger proposal, rebuild that already validated key in the ledger's exact reviewed field order. Values are unchanged and the subsequent typed `HostKey`, proposal validation, prospective history advance, durable append, readback, and stable-graph checks remain unchanged. Missing, extra, malformed, or altered values still fail closed.

The 225-case portable rootfs lease matrix and focused operation, coordinator, TypeScript, formatting, and retained-line matrices pass. H59 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
