# ADR 0217: Preserve the genesis journal key through retirement

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

H61 completed rootfs authorization and absence, final baseline observation, and `FINAL_BASELINES`. Encoding `RETIRE_INTENT` then rejected its exact genesis journal key. The lifecycle validator stored that key in local variable `key`, but every `INPUT_WA` record reused the same variable name for its `(action, path)` index, leaving the last input index in place of the genesis key at retirement.

Keep the genesis journal key immutable for the complete validator pass. Store each input write-ahead index in a separately named `input_key`. Input ordering and uniqueness checks are unchanged; `RETIRE_INTENT` and `RETIRED` again bind to the original validated genesis journal key. No evidence value, identity, or lifecycle transition is relaxed.

Focused operation, input, coordinator, TypeScript, formatting, and retained-line matrices pass. H61 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
