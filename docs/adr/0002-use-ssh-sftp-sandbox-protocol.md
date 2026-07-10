# ADR 0002: Use SSH/SFTP as the sandbox protocol

- Status: Proposed
- Date: 2026-07-10
- Reviewer: Nick Byrne

## Context

The trusted worker needs a narrow, portable protocol for command and filesystem operations in a separate VM without placing a Cogs-specific privileged daemon in the guest.

## Decision

Use OpenSSH command execution for `bash` and SFTP for `read`, `write`, and `edit`. Provision a per-session client key and an a-priori pinned, provisioner-generated guest host key. Disable agent forwarding and reject host-key changes without prompting or trust-on-first-use.

## Consequences

- The same Cogs contract can target local KVM, Kata, or a full cloud VM.
- The SSH credential is a session sandbox capability, not an integration credential.
- Tool timeouts, output bounds, atomic upload behavior, cancellation, path rules, and channel limits remain Cogs responsibilities in later stages.
- Replacing SSH with a custom guest daemon crosses `IMPLEMENTATION.md` section 47 and requires a new ADR and review.
