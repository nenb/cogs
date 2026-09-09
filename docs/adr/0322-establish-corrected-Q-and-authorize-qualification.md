# ADR 0322: Establish corrected Q and authorize qualification

- Status: Accepted
- Date: 2026-09-09
- Deciders: Nick Byrne
- Scope: exact H/G static package, mixed preflight, and seven-runner Stage2 qualification; no AWS

## Context

ADR 0325 froze implementation **H** `c10fc103532f3e3a8b746727bd0f48c6d8498148`, tree `ac76d3f83e57b9c227c74e3085bfbab6a7986f28`, and its sole first-created attempt-one producer `34282898803`, artifact `10079099187`. Protected main established control **G** `eb59cae18e0f041a243f35f253d46713f7e87142`, tree `14488a596c763088c98dcab31f713ef617432004`, with H as its sole parent and byte equality to the reviewed protected candidate.

Trusted publisher `34292774279`, attempt 1, is the sole publisher dispatch at G. It authenticated the exact producer twice before credential use, published and read back all five immutable OCI members, keyless-signed the exact immutable subject, verified its Sigstore bundle under exact issuer/workflow/G restrictions and offline transparency evidence, removed credentials, and uploaded custody artifact `10081986019` with Actions archive SHA-256 `e2c880429e08c8d923ffbd7e2af5acabe55a4b3379d1570c13b8e7dcd37c2a03`.

Publisher custody binds:

- immutable OCI manifest `sha256:6b6bc983712286fad73138e0fbf483369c708018c078508e0dbd5b93433e79fd`;
- descriptor `47dc9e90914a29f2e9aa83319faa16257727716650851a10017f9fc0671098e5`;
- publication receipt `eac17beeb291cd9a1ebfb51d7044bceb33410490210dc01233bd4e4b62984d0a`;
- Sigstore verification output `4af4df6a56eda2955cdaad7be5c7bc9ff8b8252fd46f6e11cb546edf77f08311`;
- publisher workflow `a3326fa06df9bafa214471020d7085cf7628ffccd4466611fcc0d9f377e278ee`;
- publisher log `5ec8402616fda77dbdb63aed4d72a9f97a52929af0e4fa5b422f220db2256dc5`.

One publisher audit questioned whether post-merge push-triggered CI on G had to finish before dispatch, although every required branch-protection check on G's byte-identical reviewed candidate passed before protected merge. Two independent adjudications rejected that finding. GitHub's required checks protect the current PR head or test merge; they do not require checks on the later squash commit itself. ADRs 0319, 0323, 0325, and 0326 pair pre-merge protected checks with post-merge parent/tree equality, and ADR 0325 itself cites a PR-event run as protected-check evidence. The duplicate main-push CI is useful evidence but was not a distinct temporal authorization gate. This disposition does not rely on its later success to cure a violated condition and does not transfer status records between commit IDs.

The sole first-created no-KVM static observation `34293986674`, attempt 1, then succeeded at G. It authenticated exact publisher custody, acquired only immutable fixtures, regenerated deterministic reviewed control data under H's static workflow commitment `839d0b4ba420f80d0025b30528f00b6e4f5f1872471ae27ffb8a50122d72b10c`, performed exact-ID artifact readback, removed owned fixtures, and verified the static-only runtime boundary. Artifact `10082440691` has Actions archive SHA-256 `5b294cb46261e4b36b4a7893a507ec353e585109c899f5344e643b61839f4a4f` and exactly 13 canonical members.

The observed package binds:

- static control `cfbd0e786fb530846235d85178965527250b6d8ad97def3053287c31af3f9783`;
- execution envelope `dc0db7146299cbb73e70016e56c81fe9d27a8d00ebc0924267ac7a817df9576f`;
- runtime manifest `9894454b3e15abc2c3b7f7751ed582994362da77c23bdffae7d21d320da82a16`;
- static log `6b378b2f44b0cfdf6db165131cf61bb7149cf43ebc782749fcebe889aecc809a`;
- H source manifest `ee96c1cfae2ffb1a2d8e8fc69c94d6bd792576c8885a20a78379ecfb52d2661c`;
- ten exact executable contracts for `ip`, `tc`, `nft`, `ssh`, `ssh-keygen`, `containerd`, `ctr`, `shim`, `qemu`, and `virtiofsd`.

Independent audits reconstructed all 13 bytes from H, verified all 56 selected source commitments, the canonical 4,353-entry rootfs, OCI and Sigstore custody, exact ZIP framing and modes, no selected retirement identity, and no KVM, runtime launch, AWS, provider, OpenTofu, SSM, deployment, inventory, or campaign operation. HTTPS acquisition and local filesystem work occurred and are not described as zero effects.

## Decision

Commit the exact 13 independently read-back static members without reserialization under `deploy/aws-feasibility/remote/stage2-completion-local-control-v5`. Fill only the previously blocked immutable H/G/static custody seals in `scripts/stage2-prebuilt-mixed-hg-preflight.sh` and `scripts/stage2-prebuilt-local-qualification-guard.py`, update their exact focused assertions, this decision and index, and deterministic non-authorizing readiness evidence. The qualification workflow and H-owned runtime, rootfs, grant, lifecycle, cleanup, and retirement bytes remain unchanged.

Require the protected-main squash result to be one commit whose sole parent is exact G and whose tree equals the independently reviewed candidate. Freeze that result as qualification revision **Q** only after required protected checks pass.

After Q is established and independently checked, authorize exactly one first-created attempt-one exact H/G/Q no-KVM mixed preflight. It must use H `c10fc103532f3e3a8b746727bd0f48c6d8498148`, G `eb59cae18e0f041a243f35f253d46713f7e87142`, and Q as both protected dispatch head and configured qualification head; authenticate the v5 package and exact publisher/static custody; normalize hosted `/opt`; complete immutable preparation without KVM; perform mandatory settlement twice; restore the hosted scaffold only after exact absence; and succeed without artifact authority.

Only after two independent audits accept that exact preflight may one first-created attempt-one seven-runner formal qualification be dispatched with exact H, G, Q, and preflight run ID. Each ordinal must independently authenticate H/G/Q and the v5 package, prepare one immutable rootfs, execute exactly one ordinal-bound Kata/KVM lifecycle, publish exact cycle custody, and prove fail-closed cleanup. The aggregate must authenticate all seven numeric artifacts, read back the exact package, preserve no-deletion-credit accounting, and issue only the pre-AWS qualification package.

## Consequences

Any mixed-preflight or qualification failure, cancellation, retry, malformed dispatch, missing or mismatched artifact, cleanup uncertainty, persistence uncertainty, or residue retires the complete generation. Timeout bounds observation only and never proves retirement or permits reuse.

Q or successful qualification grants no production, release, Stage3/Stage4 exit, OpenBao production qualification, AWS, provider, OpenTofu, SSM, inventory, deployment, or campaign authority. After the seven-runner qualification and independent audit, write the final non-AWS handoff and stop immediately before AWS.
