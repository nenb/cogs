# ADR 0182: Bind all command supervision to the active daemon journal

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H25 completed a certain `CTR_RUN`, recorded `RUNTIME_READY`, and retained a real Kata VM. The next reviewed host-network observation failed before fork because the command supervisor saw the deliberately retained containerd direct child but only runtime-specific ctr calls supplied its daemon profile.

Maintain one private active-daemon owner indexed by the exact in-process operation-journal object identity. Every fixed command transaction consults that registry when no explicit runtime daemon owner was supplied. If present, it must reconstruct and verify the same sealed daemon profile, require the exact sole child baseline, include the daemon and any durably admitted Kata cgroup in preexec census, and preserve the daemon during command settlement. A different journal identity, duplicate active daemon, changed process, foreign child, or foreign cgroup remains denied. Closing the daemon owner removes the registry entry before releasing descriptors.

This does not grant network code daemon authority: it supplies no daemon object and cannot signal, replace, or close it. It only lets the process supervisor account for its own already-retained direct child while executing a command authorized by the same private journal.

The root Linux retained-daemon matrix proves exact active-profile lookup, foreign-journal absence, accepted-connection operation, runtime-leaf operation, foreign failures, and removal after daemon close. H25 remains diagnostic-only. Its VM, task, container, daemon, cgroups, network, mounts, roots, and aliases were removed and independently residue-checked.

This decision grants no production fast path, qualification claim, AWS, provider, deployment, campaign, or release authority.
