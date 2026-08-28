# ADR 0214: Admit terminal input-root absence

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H58 completed removal of every staged input file, directory, manifest, private key, and input root. The final durable `INPUT_STEP` for `path: "."`, `action: "absent"` was appended, then post-append layout validation still required the input root to exist because the lifecycle phase remained `CONTAINERD_ABSENT` until the following `INPUT_REMOVED` record.

At `CONTAINERD_ABSENT`, admit physical input-root absence only when the terminal validated record is the exact root `INPUT_STEP` absence. Before that terminal record the input root remains required; from `INPUT_REMOVED` onward it remains forbidden. Existing input-step ordering, descendant retirement, held identity, remove-intent, append-generation, durable readback, and filesystem-layout checks remain unchanged. Any nonterminal, non-root, non-absence, malformed, or replaced state fails closed.

Focused operation, input, coordinator, TypeScript, formatting, and retained-line matrices pass. H58 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
