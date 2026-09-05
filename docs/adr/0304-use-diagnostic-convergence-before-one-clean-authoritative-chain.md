# ADR 0304: Use diagnostic convergence before one clean authoritative chain

- Status: Accepted
- Date: 2026-09-05
- Accepted by: Nick Byrne through explicit standing authorization for all non-AWS prerequisite work

## Context

Formal qualification `33995910136`, attempt 1, authenticated H3 `229ea62bce964086726181974a6fec1c6dfd1f86`, G3 `821149ba4c3dbccef48694efcdb1eb29fa9fd2b9`, Q3 `06188f67a9a699924d645ce8aa0e91950b6341c7`, and successful preflight `33995592875`. All seven jobs completed immutable preparation and then failed before grant or KVM entry because runner-user Python attempted to traverse the intentionally root-private `/var/lib/cogs/stage2-completion-v1/control`. Every ordinal subsequently passed recovery, fixed cleanup, independent residue, output cleanup, hosted-scaffold restoration, and final observation. The aggregate cleanup passed, and the run produced no artifacts. Full log SHA-256 is `7b8488e7e009a7e8c13952fb95a4ff3d30e5ad2bea2b10efc477aa8ca6e76b4c`.

The preflight used a different privileged observation and therefore did not exercise the formal workflow's principal transition. Repeating complete identity chains to discover workflow-glue defects is an inefficient and unsafe feedback loop. The current source count is 1,417 including this decision; the known final additive control package and decisions will exceed the former 1,420-file bound.

## Decision

Retire run `33995910136` and H3/G3/Q3 from authorization use. Preserve all historical evidence.

Extend the existing frozen-control stager with one shared root-only verifier. It must read exact fixed members through descriptor-relative no-follow opens, enforce root ownership and `0500` directory/`0400` single-link file modes, detect identity mutation, validate the complete package with H's codec, require exact directory inventories, and return only the expected descriptor digest. Formal qualification and mixed preflight must invoke this same verifier through `sudo -n env -i`; the reusable no-mint KVM diagnostic must invoke its diagnostic-control form before either route.

Use the repeatable protected-main diagnostic workflow to converge the actual full and readiness paths without minting reports, receipts, artifacts, or authority. Failed diagnostic runs remain non-authorizing and must complete recovery and residue enforcement. Use Osito only for diagnosis. A disposable root/private verifier matrix on Osito passed normal verification, real UID 65534 denial, wrong-mode, wrong-digest, hard-link, extra-member, contracts-directory, and retained-FD race cases; it grants no authority. Once one complete fresh-runner diagnostic passes and two audits agree, freeze those exact bytes and execute one clean H/G/Q chain.

Raise the tracked-source inventory bound narrowly from 1,420 to 1,460 for the measured correction plus the already-defined final control package and decisions. The byte and retained-line bounds remain unchanged.

## Consequences

No producer, publisher, static observation, preflight, or formal qualification may be dispatched for the replacement authoritative chain until diagnostic convergence passes. The diagnostic route grants no production, KVM qualification, AWS, provider, OpenTofu, SSM, inventory, or campaign authority.
