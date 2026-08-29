# ADR 0179: Claim launch network before descriptor and preserve daemon cgroup base

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-25

H22 reached production `CTR_RUN` supervision before fork. The operation launch permit had consumed and verified the runtime-network grant but had not crossed its explicit one-shot claim boundary, so descriptor issuance correctly failed. Claim the permit in the runtime owner immediately before handing it to process supervision, and bind its operation token, tokenized namespace path, and fixed mount contract.

The same diagnostic exposed pending-command recovery under a retained containerd daemon. Removing an absent or settled command leaf must not remove the shared cgroup base while the separately retained daemon leaf remains. Enumerate the already-open base after leaf removal; remove the base only when no owned leaf remains. The command leaf still counts as removed, while later daemon cleanup retains authority over its distinct leaf and the base.

Portable permit tests enforce one-shot claim. The root Linux retained-daemon matrix now proves absent pending-command cleanup leaves the exact daemon cgroup intact, and the complete native process/cgroup suite passes.

H22 failed and grants no qualification or promotion claim. Its daemon, cgroups, tokenized network, fixed roots, alias, and parent mount were identity-checked, removed, and independently residue-checked.

This decision grants no retry within an observation, production fast path, evidence, promotion, AWS, provider, deployment, or release authority.
