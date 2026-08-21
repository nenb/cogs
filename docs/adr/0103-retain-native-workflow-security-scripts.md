# ADR 0103: Retain native workflow security scripts

- Status: Accepted under the owner's instruction to implement the remaining PR 402 round-two workflow findings
- Date: 2026-08-20
- Scope: ADR 0099 local implementation and workflow only

## Context

The round-two hostile review requires the native workflow's settlement scanner and upload-receipt codec to become fixed, bounded, executable security owners with hostile tests. These scripts must remain in the centralized retained-line inventory. Before this correction, exact head `098e5d27bc5b307e7ac43a561c5265514d9557b1` already measured 48,075 conservative no-deletion-credit lines against the 48,000 hard cap. Adding the two required retained owners cannot receive deletion credit.

## Decision

Retain `scripts/stage2-native-settlement.py` and `scripts/stage2-native-upload-receipt.py` in the centralized inventory. Raise the preferred target to 49,000 and hard cap to 50,000 physical/no-deletion-credit lines. Deletions, test relocation, generated-code relocation, compressed security logic, and data-file code remain ineligible for credit; the checker remains mandatory.

This correction grants no workflow dispatch, retry, push, readiness regeneration or claim, AWS/provider/controller action, issue closure, production claim, or release authority. Existing exact-head review and mandatory execution stops remain unchanged.
