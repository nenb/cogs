# ADR 0200: Account for pre-removal netns observations

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-26

H45 completed task TERM, task removal, runtime-role retirement, and runtime-network grant release. Network removal then durably opened cleanup and recorded exact `MOUNTINFO` and `NETNS_STAT` observations before the complete runtime-network observer pass. The pass cursor expected routes first and rejected this legal, deterministic prefix.

For teardown of a retained runtime snapshot only, require that exact two-source prefix, exclude it from runtime identity derivation, and retain it in the complete source custody. Fresh forward observation remains unchanged. The cleanup intent still precedes every cleanup observation and external mutation.

H45 and its uncertain cleanup state were preserved before exact diagnostic cleanup. H44's distinct overloaded launch timeout remains non-authoritative and caused no code relaxation. Neither run minted qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
