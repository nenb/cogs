# ADR 0130: Regenerate control after immutable symlink correction

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Correct implementation H, regenerate non-KVM control data, and one replacement KVM generation

## Context

Replacement run `32586393441`, attempt 1, at control revision `223d1ddddb59391010950c1880b1ef36115f8472` passed admission, exact H/G acquisition, and the corrected root-owned control read. Immutable preparation then failed while verifying two reviewed symlinks. Runtime control canonically records symlink `size` as zero, but `_verify_installed()` compared that semantic size with Linux `lstat().st_size`, which is the link-target byte length. The immutable transaction rolled back before the sole qualification entry. No `/dev/kvm` or QMP open, containerd/Kata task, qualification network, SSH, report, receipt, or artifact occurred.

Cleanup-only recovery succeeded. Fixed cleanup and independent residue still failed because `sudo` remained the retained parent whose command line included environment values containing `cogs-stage2-local-*`; moving `env` ahead of `timeout` did not remove values from the `sudo` parent. Cleanup remains uncertain and no claim is granted. Private custody is `/Users/nenb/.pi/artifacts/cogs/issue42-local-kata-32586393441`; custody-manifest SHA-256 is `0a52b2a20f4dec28609c7b58504a8fb598dd0cffb6c143b7ee81976c8152f8df`.

## Decision

Create a new implementation revision H that:

- verifies mode for every launch artifact;
- verifies `st_size` and digest only for regular files;
- requires canonical size zero plus exact target bytes for symlinks, without treating `lstat` target-length metadata as file size;
- supervises settlement through a root wrapper mode that reads bounded fixed run identity from standard input and `execve()`s `timeout` with a fixed environment, leaving both `sudo` and `timeout` command lines free of owned marker values.

The second failed run must be bound as an exact attempt-one completed/failure predecessor alongside `32584575939`. Because this changes a source selected by the static control, the old control package cannot describe the corrected H. Produce one new non-KVM static-control observation, independently retain and validate its exact artifact, then commit a new directional G. Only after exact-head CI and hostile review may one closed-world replacement KVM generation be dispatched. Any later failure grants no implicit additional generation. The measured workflow correction high increases from 1,100 to 1,150 lines for the closed predecessor binding; the 11,000 global high and 67,000 hard limit do not change.

## Authority boundary

All work remains local/GitHub-hosted and non-AWS. This grants no AWS/provider/OpenTofu/SSM/inventory/campaign, deployment, production, promotion, release, or predecessor-cleanup authority. The process must stop before any AWS operation.
