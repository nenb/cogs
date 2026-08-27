# ADR 0207: Admit runtime-tree retirement after the exact daemon outcome

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H52 proved exact daemon and private-cgroup retirement, then removed the held `kata-runtime-v1` tree as designed. The next journal reload still had durable phase `FIREWALL_ABSENT`; its layout validator required the staged runtime tree to remain present and rejected the already completed exact removal before `CONTAINERD_ABSENT` could be appended.

At `FIREWALL_ABSENT`, continue to require the staged runtime tree unless the terminal durable record is one exact, non-uncertain `DAEMON_OUTCOME_V2` proving leader reaping, descendant reaping, empty cgroup, and cgroup removal. Only at that exact post-daemon transition may the held runtime tree be either present or absent, allowing interruption immediately before or after its identity-checked removal. `CONTAINERD_ABSENT` and every later phase continue to require the runtime tree absent. Uncertain, incomplete, nonterminal, or foreign outcomes grant no exception.

Focused operation, runtime, coordinator, TypeScript, formatting, and retained-line checks pass. H52 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
