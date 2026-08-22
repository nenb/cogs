# ADR 0128: Isolate pre-admission from action prefetch

- Status: Accepted under the owner's standing non-AWS instruction
- Date: 2026-08-22
- Scope: Sole replacement local KVM workflow job graph
- Supersedes: ADR 0127's single-job placement and workflow hash

## Context

Hostile review of revision `7409b9569821bb67216eb0891c098baefea9c3d3` found that GitHub-hosted runners resolve and download all `uses:` actions during a job's setup, before its first YAML step. Although inline admission was textually first, the same job's later upload/download actions could therefore perform authenticated source acquisition or fail before admission. No dedicated local KVM workflow had been dispatched.

## Decision

Place the action-free inline pre-admission in its own `admission` job. That job contains no `uses:` step and exports only the admitted run ID. Move workflow serialization to workflow scope. Make the `local-kata` job depend on successful admission and consume the exact admitted ID. GitHub cannot schedule or set up the action-bearing KVM/artifact job until the admission job succeeds.

The dependent job acquires G and H through explicit public `git fetch` commands under `env -i`, nonexistent HOME, fixed PATH, disabled system/global Git configuration, and disabled terminal prompting. It then revalidates exact G, H, event, actor, control bytes, workflow bytes, and the admitted run ID before immutable preparation or KVM eligibility.

The reviewed qualification-workflow SHA-256 becomes `645521ca372afaedb61256ab900605d95298dabc1e03b47a7b48bf0dac3b3a85`. The admission step is bounded to one minute; the dependent local job retains its 120-minute envelope, 115 minutes of fixed step bounds, and 21-minute post-entry reserve. Existing global and workflow line bounds remain unchanged.

## Authority boundary

This correction grants no extra dispatch. It preserves exactly one first-created attempt-one replacement Stage 2 local KVM/Kata qualification after exact-head review and CI. It grants no AWS/provider/OpenTofu/SSM/inventory/campaign, deployment, production, or release authority.
