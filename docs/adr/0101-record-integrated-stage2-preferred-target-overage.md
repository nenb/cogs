# ADR 0101: Record integrated Stage 2 preferred-target overage

- Status: Accepted by explicit owner instruction
- Date: 2026-08-18
- Scope: Stage 2 retained-line accounting only

## Context

The integrated protected-main, SSH, and runtime owners measure **43,271 conservative no-deletion-credit lines**. This exceeds ADR 0099's 42,000 preferred target while remaining below its unchanged 45,000 hard cap.

## Decision

The 42,000 value remains an advisory review target; it is not a reason to compress security logic or claim deletion credit. The central checker must report `preferred_satisfied: false`, continue to enforce the unchanged 45,000 hard cap, and stop when that hard cap is reached.

This accounting decision grants no new implementation, qualification, workflow, runtime, network, KVM, cloud, AWS, production, or release execution authority. Every ADR 0099 stop and security boundary remains unchanged.

## Consequences

The integrated owners may remain readable at the measured size. Any further counted addition must preserve no-deletion-credit accounting and must fail closed before the hard cap is reached.
