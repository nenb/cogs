# ADR 0254: Bind terminal static observation and authorize qualification

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-30

The sole V23 no-KVM static-control observation for final H succeeded on protected `main`: run `33320343092`, attempt 1, workflow head `73a5067bdc4ea6941097651beb00ebcc78e2dd9b`, implementation H `bf0479a012b39c074ecb623ea83e85b3dc3ebe36`, artifact ID `9734730708`, artifact digest `b48c6e37b516e73b186320392c810b2ab7bc3768201df9032ff010059c0ce67e`, and artifact size 37,071 bytes. Every guard, immutable-preparation, deterministic production, upload, cleanup, and static-only runtime-boundary step passed.

Exact numeric-ID readback contained 13 members and no others. The static control SHA-256 is `8932cab023904b75e959a471629a7589a7978dde50db26dc5165bf93509045a0`; execution envelope SHA-256 is `76cc3a1afe2fe140f007ebf7fdb0cbee804142593e691ff7d98288d17bcda8d3`; runtime manifest SHA-256 remains `4b37f48d7dbb0eb023ec6f05598d92f8fd88c2d98cf8a0515bb3fc042bd3a347`. The envelope binds source manifest `5d6b499de8e4a9147f7d5fdf49ec8df537b8f9db5d27c938ded59388c8544752` and the earlier H. Stage those exact readback bytes as the reviewed local control package.

Bind failed qualification run `33306125902`, attempt 1, prior H `89243c8d9f7a946aefdaa4c445a5cfe1e0fe7e14`, control head `ce1452fa8a3007b8e0d522a45341dc2d4c6bb941`, and failed conclusion as the twelfth non-authorizing predecessor. That run's recovery, exact cleanup, independent residue, and hosted scaffolding restoration passed, but it produced no report or artifact and grants no claim.

After this package and qualification guard merge on protected `main`, freeze that merge as directional control revision G describing earlier H. Authorize exactly one attempt-1 formal fresh GitHub Kata/KVM qualification with the existing immutable preparation, seven samples, 21 measurements, receipt custody, exact teardown, and zero-residue requirements. Retain all bounds and raise only the complete tracked-source cardinality bound from 1,215 to exactly 1,216 files. This grants no AWS, provider, deployment, campaign, production, release, retry, or promotion operation.
