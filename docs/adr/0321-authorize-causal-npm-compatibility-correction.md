# ADR 0321: Authorize causal npm compatibility correction

- Status: Accepted
- Date: 2026-09-07
- Deciders: Nick Byrne
- Scope: protected functional-client evidence only; no authoritative chain or AWS

## Context

Protected run `34121726291` retained one failed functional case: the current npm client completed an authenticated tarball request while the Stage 1 manifest still expected the historical npm denial. That run is immutable failed evidence and grants no authority.

The first correction changed the expectation but review found that its authority assertion was not wired to the fixture's dynamic port, failure attribution was ambiguous, and client parsing needed tighter bounds. The relay owner had only 13 gross lines remaining, which is insufficient for the producer-to-consumer regression without compressing security logic.

## Decision

Raise the relay workstream gross-line high from 1,800 to 1,900. Allocate one integration-owned ADR file slot, raising that owner from 30 to 31 and the exact total from 38 to 39. Keep the global remediation high at 18,500, the 1,460 tracked-file source limit, and every other owner and source limit unchanged.

The correction must:

1. derive the expected authority from the fixture's trusted dynamically bound port before requests are admitted;
2. require a positive bounded set of at most three authenticated npm fixture observations, with exactly one case-bound accepted intent and successful completion per request;
3. validate exact bounded tarball bytes and a bounded numeric npm version;
4. attribute any npm postcondition failure to `client.npm-tarball` with categorical expected/actual wording; and
5. preserve the failed run as historical, functional-only, non-release evidence.

A protected rerun may occur only after local tests, regenerated source bindings, accounting, and independent review. This decision does not claim registry-install, scoped-package, production Envoy, OpenBao, Stage 3, Stage 4, release, H/G/Q, preflight, qualification, or cloud readiness.

## Consequences

The additional 100-line owner capacity has no deletion credit and is not transferable. Missing or contradictory client, fixture, authority, credential, intent, completion, artifact, or cleanup evidence remains a failure. ADRs 0319 and 0320 remain reserved for a future protected-main H freeze and Q/qualification decision; this ADR grants neither.
