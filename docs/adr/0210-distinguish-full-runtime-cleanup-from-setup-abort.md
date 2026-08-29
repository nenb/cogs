# ADR 0210: Distinguish full runtime cleanup from setup abort

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H54 completed exact daemon, private cgroup, Kata-overhead cgroup, runtime-tree, network, share, and firewall removal. Appending `CONTAINERD_ABSENT` then misclassified the completed full-runtime network state as an early setup abort and attempted to validate a nonexistent `FIREWALL_ABSENT` command trace.

Classify a completed network teardown as setup abort only when no runtime was durably staged. A full lifecycle with `RUNTIME_STAGED_V3` continues through its ordinary post-firewall transition and does not receive the early-abort trace exception. Existing setup-abort behavior remains unchanged, while successful full-runtime teardown remains bound to its staged runtime and exact network records.

Focused operation, runtime, coordinator, TypeScript, formatting, and retained-line matrices pass. H54 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
