# ADR 0212: Remove redundant input-record reloads

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H56 used the reviewed 720-second settlement allowance and durably retired 839 of 1,020 input files before expiry. Together H55 and H56 show approximately twenty exact file retirements per minute because every `INPUT_GRANT`, `INPUT_WA`, and `INPUT_STEP` performed a complete journal read, parse, semantic replay, filesystem-layout validation, then immediately performed the same semantic and layout validation again in `write_validated`.

Use the already loaded exact owner state for those three append methods. `write_validated` still validates record semantics, checks the expected journal offset and held generation before append, performs the durable append/readback, and validates the resulting filesystem layout. Intent records are therefore still durably validated before their filesystem effect; settled records remain post-effect validation. Any external journal mutation, layout difference, append mismatch, or post-effect mismatch still fails closed. No records are batched, omitted, or made less durable.

Focused operation, input, coordinator, TypeScript, formatting, and retained-line matrices pass. H56 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
