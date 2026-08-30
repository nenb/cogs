# ADR 0199: Use QEMU for every task-identity recheck

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H43 reached exact ownership and began task teardown. The task helper recorded QEMU correctly, but the immediate pre-TERM and post-TERM/KILL replacement checks still selected the shim and therefore compared different roles. Use the exact QEMU role for every task-identity recheck. The durable identity, start time, executable generation, namespaces, and containerd task PID must all continue to match; shim and virtiofsd are separately covered by runtime-role retirement.

H43 and its uncertain cleanup state were preserved before exact diagnostic cleanup. It minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
