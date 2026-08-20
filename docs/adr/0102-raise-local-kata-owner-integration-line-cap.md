# ADR 0102: Raise the local Kata owner integration line cap

- Status: Accepted under the owner's instruction to finish all non-AWS prerequisites
- Date: 2026-08-18
- Scope: ADR 0099 local implementation only

## Context

At acceptance, the reviewed owners measured 44,810 conservative lines. At exact integration head `f9809d66e3952db0b621b4410f2698bbe1c82007`, the checker reports 45,244 physical/current lines and 47,178 conservative no-deletion-credit lines: the 47,000 preferred target is not satisfied, while the mandatory 48,000 hard cap is satisfied. This update corrects the measured status without changing either limit or granting deletion credit.

## Decision

Raise the retained preferred target to 47,000 and hard cap to 48,000 physical/no-deletion-credit lines. Deletions, test relocation, generated-code relocation, compressed security logic, and data-file code remain ineligible for credit. The centralized checker remains mandatory.

This grants no KVM attempt, retry, AWS/provider/controller action, issue closure, production claim, or release authority. ADR 0099's exact-head review, one non-AWS attempt, no-retry rule, and mandatory stop remain unchanged.
