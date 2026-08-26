# ADR 0187: Bind the derived Kata TAP address and complete native QMP

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H29 reached the native post-launch address inventory. Kata's coherent `mq`/`UNKNOWN`/`eui64` TAP carries exactly one IPv6 link-local address derived from its observed MAC by standard modified EUI-64. Require that exact derived address with prefix 64 and link scope only when the admitted TAP addrgen mode is `eui64`; historical no-address TAP profiles remain unchanged. Reject a changed address, prefix, scope, additional address, or address on a no-addrgen TAP.

Focused work on H28's still-live VM also completed the full independent QMP exchange after correcting native representations: process role command lines use exact role-specific sandbox arguments, the shim's sole empty argument is the value of `-publish-binary`, QMP listener inventory is read in the exact QEMU process network namespace, QMP uses canonical CRLF framing, and native QEMU 11 omits the historical false `singlestep` status member. Each form remains exact and hostile alternatives are denied.

The focused observation returned `kvm_present=true`, `kvm_enabled=true`, API version 12, exact QEMU identity, and distinct private and observer QMP socket identities. It is private diagnostic evidence only and minted no qualification. Portable hostile matrices and the root Linux network matrix pass. H29 was independently cleaned to zero residue.

This decision grants no production fast path, qualification claim, AWS, provider, deployment, campaign, or release authority.
