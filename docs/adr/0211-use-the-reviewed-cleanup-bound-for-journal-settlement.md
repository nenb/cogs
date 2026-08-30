# ADR 0211: Use the reviewed cleanup bound for journal settlement

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H55 passed the corrected `CONTAINERD_ABSENT` transition and began exact input retirement. It durably removed 592 of 1,020 staged input files before the operation filesystem control reached its 5,430-second total deadline. The existing settlement component reserved only 30 seconds, although the formal lifecycle already allocates and enforces a reviewed 720-second cleanup/recovery bound. No process, network, firewall, runtime-tree, private-cgroup, or Kata-overhead residue remained.

Keep the measured 4,200-second setup and 1,200-second SSH/workload components unchanged. Set only the journal settlement component to the existing reviewed 720-second cleanup bound, producing a 6,120-second internal journal total that remains below the fixed 7,800-second outer lifecycle deadline. This does not add retries, relax identity checks, alter evidence semantics, or exceed any formal workflow bound.

Focused operation, input, coordinator, TypeScript, formatting, and retained-line matrices pass. H55 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
