# ADR 0339: Row 4 first-attempt correction batch

## Status

Accepted under the owner's explicit instruction to continue Rows 4–10 while
stopping before AWS.

## Decision

Product run `34736648989` attempt 1 and KVM run `34736650134` attempt 1 at
protected source `09e586c2377738fabeee9d6900bf4b3f89c94372` failed. Both are
non-authoritative: neither is success evidence nor authorizes reuse.

This ADR authorizes only the bounded source corrections, focused tests, and,
later, readiness, full validation, and PR work. After merge it authorizes one
fresh replacement candidate. It does not authorize a same-byte retry, H/G/Q,
Docker or KVM execution, or AWS, OpenTofu, SSM, or network effects. Uncertain
cleanup remains failure, not success or retry authority.

## Accounting

ADR0338's literal task matrix admits this batch without changing any task,
global, hard-cap, reserve, or source-inventory cap. Accounting remains
cumulative from its protected checkpoint: deletion and replacement provide no
credit.
