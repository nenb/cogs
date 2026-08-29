# ADR 0184: Admit the runtime cgroup after certain local launch

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H26 again reached a certain successful `CTR_RUN` and `RUNTIME_READY`. The first host-network observer then rejected Kata's exact runtime cgroup because ADR 0180 admitted it only after `CTR_LAUNCH_ISSUED_V1`. That observation record is intentionally cycle-route evidence and is absent from the route-free private local qualification, even though the canonical command intent and certain outcome are durable.

Admit the deterministic `kata_cogs-stage2-ssh-v1` leaf after either the cycle launch observation or exactly one canonical `CTR_RUN` intent paired by serial and binding with exactly one certain, non-uncertain, status-zero exited outcome. Before the outcome, after an uncertain or nonzero outcome, under duplicate/mismatched records, or with any other leaf name, the census remains denied.

The root retained-daemon matrix now exercises the route-free successful-outcome predicate rather than relying on a launch-observation fixture. H26 remains diagnostic-only. Its VM, task, container, daemon, cgroups, network, mounts, roots, and aliases were removed and independently residue-checked.

This corrects ADR 0180's predicate without changing cycle evidence semantics and grants no qualification claim, production fast path, AWS, provider, deployment, campaign, or release authority.
