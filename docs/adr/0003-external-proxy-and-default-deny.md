# ADR 0003: Keep credential injection outside the VM behind default deny

- Status: Accepted
- Date: 2026-07-10
- Reviewer: Nick Byrne

## Context

Guest root can compromise an in-VM proxy, read its memory or CA key, and alter guest firewall rules. Explicit proxy variables alone are bypassable if direct egress remains available.

## Decision

Place the trusted explicit HTTP/HTTPS proxy, real credentials, and CA private key outside the sandbox VM. Enforce default-deny guest egress externally so ignoring proxy configuration fails closed. The guest receives only the public CA, a non-secret placeholder, and a short-lived session proxy capability. Unsupported auth classes, destinations, methods, paths, protocols, UDP/QUIC, and bypass attempts fail closed.

The concrete proxy remains undecided until Stage 1 compares pinned candidates using the same conformance suite.

## Consequences

- Guest root is compatible with the credential-value guarantee.
- The proxy cannot prevent confused-deputy use or source exfiltration to an approved write-capable route.
- Any relaxation of external default deny or movement of secret-bearing proxy state into the guest crosses an ADR boundary.
