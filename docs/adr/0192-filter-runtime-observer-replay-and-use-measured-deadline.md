# ADR 0192: Filter runtime observer replay and use the measured deadline

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H34 reached `RUNTIME_READY` but failed before the guest observation because runtime replay indexed every command intent in that lifecycle phase. The network owner had already journaled its exact IP, tc, and nft observations in the same phase. Replay must select only the three fixed ctr observer command IDs before applying their required order; unrelated durable network observations remain independently validated by their owner.

Failure cleanup then measured a native ctr observer exceeding the five-second bound under validation load: the first observer consumed approximately eight seconds of wall time and the following ctr info reached its absolute deadline. Raise only the fixed observer command bound from five to fifteen seconds. Other command classes and global lifecycle bounds are unchanged.

H34 remains diagnostic-only and minted no qualification. Its uncertain cleanup outcome was preserved; the retained task, container, daemon, VM, network, cgroups, mounts, and state were independently identity-checked, removed, and residue-checked before another lifecycle.

This correction grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
