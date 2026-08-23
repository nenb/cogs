# ADR 0138: Preserve pre-operation primary and bind sixth KVM failure

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-23

Run `32614828572`, attempt 1, passed exact preparation and entered privileged Python. It failed after about 64 seconds with the secondary `exact retired journal owner result required`. Fresh recovery, fixed cleanup, independent residue, and output cleanup all passed; no artifact was produced. Private custody SHA-256 is `4a31a5ff009dc41d4b26a4fb8216109cd53d716ab637dfff79a28f4e7d5b5ec1`.

The traceback proves static custody existed but the operation owner had not returned. A primary in rootfs acquisition or fallible operation opening left `lifecycle.operation` unset. Cleanup then returned without a journal-backed terminal owner and the coordinator incorrectly called normal evidence, masking the retained primary with a secondary retired-owner error.

Correct H before another observation. Track a fixed allowlisted forward stage, preserve the original primary as the exact cause when no operation owner was established, never enter normal evidence from that state, and emit only one bounded fixed diagnostic from the top-level result entry. Do not weaken retired-journal types, fabricate pre-operation evidence, infer absence from an unset Python field, or allow recovery to mint evidence. Add assignment-boundary regressions proving custody abort occurs once and normal evidence is unreachable.

This correction is diagnostic and terminal-contract hardening. It may reveal a separate underlying rootfs/operation-open defect; it does not claim to correct an unknown primary. Because H changes, require a new static-control observation and later directional G before any further KVM observation. Bind `32614828572` as the sixth exact failure in any later closed history.

The owner's standing authorization permits the non-AWS H/static/G diagnosis cycle. It grants no AWS/API/credential/provider/OpenTofu/SSM/inventory/campaign, deployment, production, promotion, or release authority.
