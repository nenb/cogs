# ADR 0349: Freeze replacement H and authorize control

- Status: Accepted
- Date: 2026-09-14
- Decider: Nick Byrne
- Scope: replacement H, exact producer, additive retirement V2, direct-child G, publisher and static observation; no AWS

## Context

ADR 0348 retired implementation `9ae1f21bf655081f03f4e2f3eb890ffa11de9b3e` and its sole failed producer `34831612221`. PR 549 passed every required protected check and merged as replacement implementation **H** `1ef6aae3506fded805d8277ec4bce02e585c0650`, tree `3e83fc44cbcfd4ad1be7b9f41365dfca90f6e853`, whose sole parent is `9ae1f21bf655081f03f4e2f3eb890ffa11de9b3e`. The reviewed candidate tree and protected H tree are equal. Protected-main CI `34845151154` and Linux foundations `34845151161` passed.

Exact-H Product diagnostics passed both profiles on a fresh disposable Linux/x86_64 VM and the VM was deleted after zero Docker, cgroup and fixed-root residue was proved. The accepted diagnostic generations are empty `639dab84272891e68b90c0928f8e1cc6` and nonempty `d925e0980d7342e110fb075b9aab6190`; both bind source inventory `sha256:96cf82fdc11cfded6c891ab53837b21c03b9d5ce7fe7853a3303e01cffdc6385` and H's exact tree. Earlier environment-setup and helper-timeout diagnostics grant nothing.

Three distinct direct KVM diagnostic runs `34845199194`, `34845214303`, and `34845228681`, each attempt 1, passed exact-H KVM qualification, isolated driver smoke, schema checks and namespace/lease cleanup without artifact authority.

The sole protected pair then passed:

- Product run `34852537897`, attempt 1, with candidate artifacts `10350814886` and `10350594286` and probe artifacts `10351720444` and `10350199676`. Independent readback verified all archive digests, both profile receipts, exact H/tree/source inventory, two candidate generations, all sixteen distinct retired probe generations, complete capability coverage, root-controlled generation locks and certain cleanup.
- KVM run `34852537647`, attempt 1, artifact `10351484234`, archive digest `sha256:7ce804eb6ed5c72fa13fe7f504e97047fc2879085c8aef5d4820dffb4a2a997f`. Independent schema and semantic validation accepted exact H, KVM/root/distinct-boot qualification, isolated driver smoke and cleanup.

Producer run `34853517895`, attempt 1, is the sole first-created producer at H. Its admit, build and readback jobs passed. Artifact `10352673587`, named `stage2-prebuilt-rootfs-1ef6aae3506fded805d8277ec4bce02e585c0650`, is unexpired and has Actions archive digest `sha256:e28f0687ade20140f8a25ce7e55b0be2aa2f81cd04f0a4a96672d1f271d8f56c`. Independent readback and the closed publisher validator accepted all seven members and these bindings:

- source manifest `09cadffc28159e2f459d0da2003648934710baed9c6a5d29132b0f0ae2300314`;
- workflow `517173a63ad7379fbeef762ae61865ceaac9b275798ce22512f60ceefda3dcef`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `99cd6d8b4b5df5bfee94f8657358cbf40f4a707122e966b6734105729fecf45f`;
- package `085887783a0ca00b013e0c5b33ce760d20d072b33afe316dbf21bbfa31a6d79a`;
- provenance `3c2a1d227a78999a613ff9cec5b4ef6dc9c2afa8a1e2a0092ce8b30bd7d37c7e`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`, manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`, metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`, 4,353 entries and two byte-identical builds.

No producer KVM, AWS, provider, OpenTofu, SSM or remote publication occurred.

## Decision

Freeze exact H `1ef6aae3506fded805d8277ec4bce02e585c0650`, producer run `34853517895`, artifact `10352673587`, and archive digest `sha256:e28f0687ade20140f8a25ce7e55b0be2aa2f81cd04f0a4a96672d1f271d8f56c`.

Preserve `config/stage2-retired-revisions-v1.json` byte-identically at SHA-256 `2fe7b704438d9e3f7493ee8be43760ac9f213d095d5411bee137126bc72153b5`. Publish additive closed V2 with that predecessor binding and add only retired H `9ae1f21bf655081f03f4e2f3eb890ffa11de9b3e` and failed producer `34831612221`. Update the closed Python selector and all nineteen pre-effect workflow mirror occurrences together. Retirement remains an exact selection veto, never ancestry rejection, authorization or cleanup authority.

Establish the protected-main squash result containing this decision, additive V2 policy/selector/mirrors, focused tests, accounting assertions and deterministic non-authorizing readiness refresh as control revision **G** only if it is one commit whose sole parent is H, its tree equals the reviewed candidate tree, and every required protected check passes. H remains the executable implementation and producer identity. G changes no H-owned runtime, rootfs, image, network, provider or campaign behavior.

After G is established and independently checked, authorize exactly one first-created attempt-one trusted publisher at G with the frozen H, producer run, artifact ID and archive digest above. Only after independent publisher audits and fresh exact runner-image convergence may exactly one first-created attempt-one no-KVM static observation run at G. Independently audit its exact artifact and cleanup before creating Q.

Q must be G's sole direct child. It may contain only the exact independently read-back static members, final H/G/Q custody seals, focused assertions, its decision/index, and deterministic non-authorizing readiness refresh. It must not change H-owned executable authority.

Use the existing final-HGQ reserve for the literal G/Q paths. Keep every task line/byte cap, the 21,500,000-byte tranche, 132,000-line hard stop, source limits and no-deletion-credit accounting unchanged.

## Consequences

A failed, cancelled, retried, malformed, expired or cleanup-uncertain publisher or static run retires this generation and grants no downstream authority. No fallback or same-generation replacement is permitted.

This decision grants no mixed preflight or qualification until exact Q exists, and no AWS, credentials, provider initialization, OpenTofu, SSM, inventory, deployment, campaign, production, release or Issue 42 closure authority. After successful Q, mixed preflight, seven-runner qualification and final handoff, stop immediately before AWS.
