# ADR 0164: Accept exact OpenSSH public-key comment shapes

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

The first successful native executable handoff reached input creation. Ubuntu 24.04's pinned `ssh-keygen -y` emitted the private key's fixed comment, while input custody expected the older comment-free two-field form. The generated `.pub` file, derived key type, key blob, command identity, exit status, stderr, and durable output were otherwise exact.

For each one-shot public-key derivation, accept only either the exact generated public line or that same line with its final fixed comment removed. Continue to reject every other byte, malformed key, stderr, truncation, nonzero status, uncertain process outcome, or identity drift. Both accepted forms bind the same key type and key blob already validated against the private key; comments carry no authentication authority.

This is input compatibility for the pinned native OpenSSH behavior. It does not permit command retry, alternate keys, mutable caller input, AWS, provider, deployment, evidence, promotion, or release authority.
