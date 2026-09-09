# ADR 0329: Establish runtime-corrected Q and authorize qualification

- Status: Accepted
- Date: 2026-09-09
- Deciders: Nick Byrne
- Scope: exact H/G static package, mixed preflight, and seven-runner Stage2 qualification; no AWS

## Context

ADR 0328 froze implementation **H** `c30e0d69ec374cd812ff361e670e974d51b661c4`, tree `3d7d09811a780ec4d3eef99d8afac5f1ec4dcd32`, and its sole first-created attempt-one producer `34375934829`, artifact `10114901253`. Protected main established control **G** `15d99b55f4910df94decdd7edcc80bf95aee492d`, tree `9452fe506929db2ae92955b9b1249d06c28a16cb`, with H as its sole parent and byte equality to the reviewed candidate. Required and Linux/root checks passed on both the candidate and protected G.

Trusted publisher `34402409489`, attempt 1, is the sole publisher dispatch at G. It authenticated the exact producer twice before credential use, published and read back all five immutable OCI members, keyless-signed the exact immutable subject, verified its Sigstore bundle under exact issuer/workflow/G restrictions and offline transparency evidence, removed credentials, and uploaded custody artifact `10123988189` with Actions archive SHA-256 `8fcf54f1d4e452eebc8c84e6276f710ba3679d6ec605a3764b42c57d55ed7bec`.

Publisher custody binds immutable OCI manifest `sha256:677f7fd30007158c524be6e0dd32236982ea5317481988458c8931792b981f38`, descriptor `3ab1238a7424a400f6ad306611218f4434190d7ae040c6bd5acb31b91b1d81a1`, publication receipt `56bbc6c708168c594208f6f8431695a10d02458e7a8d1e223a12d7bb02f64586`, Sigstore verification output `2600b4009177f4dd52610e5338fa6b8b59a4e38dc5ea1c9e17a9457367cf8014`, publisher workflow `e299797b98873c1c0c701349b667879ce2999f0da4f182569f02f57f807e0ee1`, and publisher log `da145edf9ecee2c52e8736899fbcd9176cfb0497ba6b351a297cee55550f2844`. Two independent audits accepted the exact ORAS, Sigstore, archive, and readback custody.

The sole first-created no-KVM static observation `34403562378`, attempt 1, then succeeded at G. It authenticated exact publisher custody, acquired only immutable fixtures, regenerated deterministic reviewed control data under H's static workflow commitment `95b65c998b70f028b091de60c868de5e94b68703327cf5f66760a9e5b0fae438`, performed exact-ID artifact readback, removed owned fixtures, and verified the static-only runtime boundary. Artifact `10124443866` has Actions archive SHA-256 `06c3067a3c0a48672c5832404c66e61773a947abdae30e038d113cfc6e08d6c2` and exactly 13 canonical regular members.

The observed package binds static control `83a9c5d15705406961b357963312fdea132757dd19d51c15c0ae6a082173bb7e`, execution envelope `511fb5c2b4f6f85b3ecf2d955fbad1d39b196d99562c7a6aeff014f70c1d1943`, runtime manifest `39bc92cc51d844d4d706ad352773e44d521b5aaaa76d1d389f273032d6120871`, static log `db74335577e71a8830496394f326bbb9ccb8a9e8baef0056c9f13107953ffaf4`, H source manifest `a5ebebaf515805f65bb2ff7c4ffa79ff1506ee8859e5257763c98dd00114503f`, and ten exact executable contracts for `ip`, `tc`, `nft`, `ssh`, `ssh-keygen`, `containerd`, `ctr`, `shim`, `qemu`, and `virtiofsd`.

Two independent audits reconstructed all 13 bytes from H, verified all 79 selected source commitments, the canonical 4,353-entry rootfs, OCI and Sigstore custody, exact ZIP framing and modes, complete singleton history, no selected retirement identity, and no KVM, runtime launch, AWS, provider, OpenTofu, SSM, deployment, inventory, or campaign operation. HTTPS acquisition and local filesystem work occurred and are not described as zero effects.

## Decision

Commit the exact 13 independently read-back static members without reserialization under `deploy/aws-feasibility/remote/stage2-completion-local-control-v6`. Fill only the previously blocked immutable H/G/static custody seals in `scripts/stage2-prebuilt-mixed-hg-preflight.sh` and `scripts/stage2-prebuilt-local-qualification-guard.py`, update their exact focused assertions, this decision and index, and deterministic non-authorizing readiness evidence. The qualification workflow and all other H-owned runtime, rootfs, grant, lifecycle, cleanup, contract, and retirement bytes remain unchanged.

Require the protected-main squash result to be one commit whose sole parent is exact G and whose tree equals the independently reviewed candidate. Freeze that result as qualification revision **Q** only after required protected checks pass.

After Q is established and independently checked, authorize exactly one first-created attempt-one exact H/G/Q no-KVM mixed preflight. It must use H `c30e0d69ec374cd812ff361e670e974d51b661c4`, G `15d99b55f4910df94decdd7edcc80bf95aee492d`, and Q as both protected dispatch head and configured qualification head; authenticate the v6 package and exact publisher/static custody; normalize hosted `/opt`; complete immutable preparation without KVM; perform mandatory settlement twice; restore hosted scaffolding only after exact absence; and succeed without artifact authority.

Only after two independent audits accept that exact preflight may one first-created attempt-one seven-runner formal qualification be dispatched with exact H, G, Q, and preflight run ID. Each ordinal must independently authenticate H/G/Q and the v6 package, prepare one immutable rootfs, execute exactly one ordinal-bound Kata/KVM lifecycle, publish exact cycle custody, and prove fail-closed cleanup. The aggregate must authenticate all seven numeric artifacts, read back the exact package, preserve detailed 90-day cycle evidence and no-deletion-credit accounting, and issue only the pre-AWS qualification package.

## Consequences

Any mixed-preflight or qualification failure, cancellation, retry, malformed dispatch, missing or mismatched artifact, cleanup uncertainty, persistence uncertainty, or residue retires the complete generation. Timeout bounds observation only and never proves retirement or permits reuse.

Q or successful qualification grants no production, release, Stage3/Stage4 exit, OpenBao production qualification, AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign authority. After the seven-runner qualification and independent audit, write the final non-AWS handoff and stop immediately before AWS.
