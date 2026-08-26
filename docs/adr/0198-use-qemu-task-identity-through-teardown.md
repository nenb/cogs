# ADR 0198: Use QEMU task identity through teardown

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H42 completed all forward work and recorded exact runtime ownership. The teardown task helper still selected the shim while matching containerd's task PID, repeating the representation mismatch corrected for forward observation. Select the exact QEMU role throughout task TERM/KILL observation and durable task-identity checks. QEMU replacement remains fail-closed; shim and virtiofsd retirement remain independently bound by the complete runtime-role identities.

H42 and its uncertain cleanup state were preserved before exact diagnostic cleanup. It minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
