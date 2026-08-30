# ADR 0224: Verify unlinked observer configuration at retirement

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

H68 reached observer-configuration retirement, but the final verification compared the held active configuration against its pre-cleanup stat identity. Exact runtime-tree removal had intentionally unlinked that inode, changing link count and ctime while the retained descriptor still named the same immutable generation and bytes.

At retirement, continue to verify the base configuration with its complete original identity. For the active derived configuration, require the same device, inode, mode, uid, gid, size, and mtime; accept only either the original link/ctime pair or link count zero after retirement. Read through the retained descriptor under a stable current identity, then rederive and rehash the exact active bytes before closing custody. Changed bytes, replacement generation, relinking, metadata drift beyond the exact unlink transition, or read instability fails closed.

Focused admission, mutable-bridge, coordinator, TypeScript, formatting, and retained-line matrices pass. H68 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
