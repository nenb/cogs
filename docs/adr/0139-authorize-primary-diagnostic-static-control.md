# ADR 0139: Authorize primary-diagnostic static control

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-23

Implementation H `4bced3fb4b768f5dc67f919ae8d579059739b126` preserves pre-operation primary custody and emits bounded lifecycle diagnostics as required by ADR 0138. Exact-head CI and hostile review passed. H changes selected execution bytes, so prior static control cannot authorize another observation.

Authorize one no-KVM static-control observation for exact H. Extend authenticated static history with successful run `32600501461`, attempt 1, workflow head `e9e4ea6aef35c9d4cb821e2fcc6adf480eec87f3`, reviewed H `1eaec52dd4e2f1222548362e92adc780a2169025`. Update the exact embedded guard and static runtime-boundary workflow digest. Every outcome consumes this static observation; no rerun follows automatically.

The artifact remains non-authoritative until exact-ID private readback and hostile review. This grants no KVM replacement by itself and no AWS/API/credential/provider/OpenTofu/SSM/inventory/campaign, deployment, production, promotion, or release authority.
