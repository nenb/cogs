# ADR 0285: Bind the launch-observation-corrected diagnostic producer

- Status: Accepted
- Date: 2026-09-02
- Accepted by: Nick Byrne through the standing corrected non-AWS instruction

## Context

No-mint rehearsal `33615698328` authenticated, launched the Kata task, and reached SSH authentication, then correctly refused the SSH intent because successful `CTR_RUN` had structurally skipped the required durable launch observation. Cleanup uncertainty granted no authority; readiness was not entered, no evidence was minted, and no AWS/provider operation occurred.

PR #497 loads cycle route custody for only CTR_RUN and the two SSH route commands in non-recovery execution, allowing exact successful CTR_RUN to append `CTR_LAUNCH_ISSUED_V1` while ordinary setup commands and recovery remain authority-free. Complete local validation passed 1,325 tests with seven explicit skips and zero failures, and protected CI passed. The protected-main implementation revision is `9f6e79140e4df284588182c96b5044bb52f50ef9`.

Attempt-one producer `33626103650` completed two byte-identical builds and independent seven-member readback. Artifact `9845676644` has Actions digest `sha256:7931eda1e35d4d5a4630c8bffc12bc42a003ebf88b5c938e3564f8422817cbdc`.

## Decision

This ADR must be the direct protected-main child of `9f6e79140e4df284588182c96b5044bb52f50ef9`. It authorizes one first-created diagnostic publisher bound only to run `33626103650`, artifact `9845676644`, and that exact archive digest, followed by one no-mint full/readiness rehearsal if publication succeeds.

It freezes neither H nor G and authorizes no AWS/provider operation.

## Consequences

All prior diagnostic generations and failed rehearsals remain non-authorizing. No complete full/readiness KVM rehearsal has occurred.
