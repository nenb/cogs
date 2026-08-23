# ADR 0149: Correct rootfs-operation integration from private Linux diagnostics

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

Private non-authoritative execution on the owner's Ubuntu 24.04 physical KVM host reproduced the hosted failure and identified six adjacent integration defects before any KVM entry: production omitted the existing rootfs bootstrap; retained topology compared refreshed chain-component wrappers rather than their exact retained nodes; lease marking retained a stale state generation; operation layout rejected the immutable preparation root and prepared runtime that static custody still requires; and opening the exact Kata operation changed the completion-parent generation before rootfs verification.

Bootstrap the rootfs state once at acquisition. Preserve exact node identity while accepting refreshed wrapper values, and refresh the state generation after lease marking. Admit only the exact immutable preparation name and phase-correct prepared-runtime presence. Refresh only the authenticated completion-parent transition whose names are exactly the five reviewed roots, whose key/mode/owner are unchanged, and whose directory link count increases by one; then revalidate both chains before verification.

Raise the integrated operation/rootfs owner line high from 3,220 to 3,260 for this measured transition. Keep the global, deployment, retained, workflow, preferred, and hard highs unchanged. Private monkeypatches and timeout extensions grant no evidence or production authority; production bounds remain unchanged. No AWS/API/provider/deployment/promotion/release authority follows.
