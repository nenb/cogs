# ADR 0320: Freeze corrected H and authorize control

- Status: Accepted
- Date: 2026-09-08
- Deciders: Nick Byrne
- Scope: corrected Stage2 H, exact producer, direct-child G, publisher, and static observation; no AWS

## Context

ADR 0323 retired H `0296252721fad0502dd4f41dacb1674e71b42bd6` and required a distinct authoritative production Pi-turn deadline plus sticky malformed-successful-SFTP-handle ownership. PR 524 passed the required source reviews, deterministic evidence regeneration, full local checks, protected CI, the isolated greater-than-60-second composed regression, Stage2-only KVM, insecure-container, and every Linux/root lifecycle shard. Protected rebase produced corrected implementation **H** `97bc8eb8520a2116914c65a9ec5929e82c34ebf3`, tree `655bc8eab6960cce89daa793989abe7bc6f166ea`. The reviewed candidate and protected H trees are equal.

The scoped KVM gate is successful run `34182039267`, attempt 1. Insecure-container run `34182039199`, attempt 1, and the isolated long-turn run `34180438707`, attempt 1, also passed the exact reviewed candidate tree. CI run `34180403502` and Linux/root lifecycle run `34180403463` passed. An earlier non-Stage2-only KVM invocation `34180468141` attempted the separately scoped Stage1 Envoy suite inside the exclusive namespace and failed listener readiness; guest destruction, namespace retirement, evidence publication, and domain cleanup succeeded. It is diagnostic, non-authorizing, and is not substituted for the successful exact-tree Stage2-only gate.

Producer run `34183885618`, attempt 1, is the sole first-created producer at H. Its `admit`, `build`, and `readback` jobs passed. GitHub artifact `10040293103`, named `stage2-prebuilt-rootfs-97bc8eb8520a2116914c65a9ec5929e82c34ebf3`, is unexpired and has Actions archive digest `sha256:25f3476b9ba0a49ec20bb6935cea89a3fbb4b7123ed75aacfcdf676351e04e79`.

The producer binds:

- source manifest `377f30d4ab589cb2c6cd9f0c55043399c300363020c6475b15a977c375ba6c47`;
- workflow `83e975af3f210a22fd059860cddeaa68712928f24e7a7e1751f02cb673e25ae2`;
- input contract `fe524cc5caafab7f6bb10ef9ebcac40903c1b1bdd60e8ebbf21919bfa788a341`;
- producer receipt `a3f84d0842981198b7f9e36880726daa779a4141da561795f89fe9606521a97c`;
- package `6ce8fb7faccb57930cb8ec45794131aa66a3e9edb298e5a00e1bd08bf6b9c3a1`;
- provenance `c1e4a7d3eb2b9ea805d3cfe92ffed8af1cc295810b8b0bec12e4d35943a8b96d`;
- canonical ustar `41951eee6ee10211fa716962dd6e2641c319a816b89d0fc31fe114872addc397`;
- manifest `59ae5c5840fffca4ec24f4d720bca7a3f1ecb85e2950d8a7a3db7a3315c321d1`;
- metadata `8bb789127187f3687d1452a4690c4b700fd99ad9e9c97469b726541fad972506`;
- sentinel `96ff5f11e4117ac8b22196a2216a52722eb16577dd3f28598e6ca4ebf28f70c0`;
- 4,353 entries and two byte-identical builds.

The producer log SHA-256 is `1a74db884d1e8e58deec129d044dbfb140057075d3166cd26ecaf047b4eba076`. Two independent audits found no P0–P3 issue and confirmed no AWS, provider, OpenTofu, SSM, KVM, deployment, campaign, or remote rootfs publication effect.

Model-key revocation after hydration into a live worker remains unresolved. OpenBao deletion alone does not invalidate that provider key; containment requires verifiable worker retirement/replacement and provider-side revocation where available.

Pre-G review found that the frozen publisher and static workflow guards partitioned prior runs by caller-controlled display-title inputs. A failed run with different inputs could therefore be omitted from a later run's first-created query at the same G. Before either lane is authorized, G must remove that partition and count every workflow-dispatch run of the same workflow at exact G. This changes control-plane admission only; it does not change H's runtime, rootfs, grant codec, or qualification executable source.

## Decision

Freeze H `97bc8eb8520a2116914c65a9ec5929e82c34ebf3` and the exact producer observation above.

Establish the protected-main result as control revision **G** only if it is one commit whose sole parent is H and all required protected checks pass. Its closed changed-file set is this decision, its index, the two publisher/static first-created predicates, their focused guards, the reservation/accounting guard alignment, and deterministic non-authorizing evidence refresh. H remains executable runtime identity; G independently records the producer and supplies the corrected control-plane admission used by publisher and static observation. G does not replace H in producer provenance or alter H-owned runtime/grant semantics.

After G is established and independently checked, authorize exactly one first-created attempt-one trusted publisher at G with these immutable inputs:

- implementation H `97bc8eb8520a2116914c65a9ec5929e82c34ebf3`;
- producer run `34183885618`;
- producer artifact `10040293103`;
- producer archive digest `sha256:25f3476b9ba0a49ec20bb6935cea89a3fbb4b7123ed75aacfcdf676351e04e79`.

The publisher's first-created predicate must count every publisher workflow-dispatch run at exact G without filtering on caller-controlled title or artifact input. Only after the publisher completely succeeds and two audits accept its exact ORAS, Sigstore, descriptor, artifact, and readback custody may one first-created attempt-one prebuilt no-KVM static-control observation run at the same G using the publisher's exact run/artifact/archive identities. The static predicate likewise counts every static workflow-dispatch run at exact G without filtering on caller-controlled title or H input. Audit the static observation twice before any Q commit.

ADR 0322 remains reserved for committing only the exact independently read-back static package as sole-parent Q and authorizing mixed preflight and seven-runner qualification. Q must not change H-owned executable authority.

## Consequences

A failed, canceled, retried, malformed, artifactless, expired, residue-uncertain, or cleanup-uncertain publisher or static run retires this generation and cannot be repeated for authority. H or G alone grants no mixed preflight, qualification, production, release, Stage3/Stage4 exit, AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign authority.

This decision implements the owner's explicit authorization to continue the non-AWS authoritative chain and stop before AWS. It grants no AWS operation under any circumstance.
