# ADR 0197: Bind the native Kata task PID to the QEMU role

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H41 completed runtime proof, causal network proof, production SSH, and all 21 measurements. Cleanup ownership then compared containerd's task PID with the shim PID. Native Kata/containerd reports the QEMU PID as the task PID; H41's exact values were task `3761024`, QEMU `3761024`, and shim `3761013`.

Bind task ownership to the already exact-classified QEMU role. The shim, QEMU, nested virtiofsd roles, ancestry, executable generations, namespaces, cgroups, container metadata, and share identity remain independently required. A missing or non-exact QEMU role still yields preservation, never ownership.

H41 and its uncertain cleanup state were preserved before exact diagnostic cleanup. It minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
