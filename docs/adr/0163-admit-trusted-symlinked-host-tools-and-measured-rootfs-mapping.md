# ADR 0163: Admit trusted symlinked host tools and measured rootfs mapping

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

A clean private observation measured each full retained-rootfs verification at 140 seconds, exceeding the live-mapping owner's 120-second bound. A diagnostic 300-second owner completed four checks. The next exact failure showed Ubuntu 24.04's reviewed `/usr/sbin/ip` is a root-owned symlink to `/bin/ip`; executable custody incorrectly required every declared host path and closure library name to be a non-symlink. It then compared producer-sorted `DT_NEEDED` names against ELF order and retained the ELF interpreter for libraries even though the reviewed producer intentionally records interpreters only for executable roots.

Raise only the read-only live-rootfs mapping verification to 300 seconds. For reviewed host executable contracts, resolve at most 40 administrator-owned symlinks below `/`, rejecting escapes, foreign identity, writable directories, replacement, aliases, or byte/ELF drift, and retain the resolved regular descriptor. Keep fixed source/control and active Kata configuration traversal no-follow. Normalize retained ELF metadata exactly as the producer does: executable-only interpreter and sorted dependency names.

This adds no mutable effect, retry, AWS, provider, deployment, evidence, promotion, or release authority. A timeout or any path/identity mismatch remains a preserved failure.
