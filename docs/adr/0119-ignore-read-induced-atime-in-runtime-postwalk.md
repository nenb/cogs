# ADR 0119: Ignore read-induced atime in runtime postwalk stability

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Immutable runtime archive observation

## Context

A full pinned Linux/amd64 Docker execution after ADR 0118 reached the extracted-tree postwalk and showed that reading a regular file and enumerating the staging root can update access time. Python `stat_result` equality therefore rejected unchanged files and directories even though all security-relevant identity, mode, ownership, link count, size, mtime, and ctime fields remained stable.

## Decision

Use the existing exact `_same_file_generation` comparison for pre/post regular-file and postwalk-root observations. It compares device, inode, mode, UID, GID, link count, size, mtime, and ctime while deliberately excluding atime. Content is still read completely through a no-follow descriptor and hash-bound. Any identity, metadata, content, or structure change remains fatal.

## Authority boundary

This local non-AWS correction grants no KVM result, AWS/provider/OpenTofu/SSM/inventory/campaign, production, or release authority.
