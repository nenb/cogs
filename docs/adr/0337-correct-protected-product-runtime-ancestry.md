# ADR 0337: Correct protected product runtime ancestry after the protected squash

## Status
Accepted bounded non-AWS runtime correction. It supersedes ADR0336 only for the failed product-source ancestry and its final prospective allocation; it grants no readiness, dispatch, Docker/KVM, AWS/provider, release, retirement, or H/G/Q action.

## Decision
Protected product run `34688544414`, attempt 1, selected protected candidate `eda2dc499153f3053772790c02ea6d332403742e` and failed before application execution because the hosted `/opt` ancestry was unsafe. No product application, image build, qualification, evidence authority, H/G/Q identity, or retry claim resulted. `eda2dc49` is a product candidate/checkpoint only, never H, G, or Q.

The protected source is now exactly `/var/lib/cogs-product-test/protected-$candidate`. Its direct parent is root-owned mode `0700`; root verifies that parent before creating the source, and the later root inventory verifies the source separately from the 32-hex generation directory and root evidence receipt. `/opt` is not an ancestry dependency. The existing root-owned source closure, no-follow checks, immutable receipt binding, and 32-hex generation filter remain required.

## Accounting and closure
Protected squash `eda2dc499153f3053772790c02ea6d332403742e`, tree `9ad48a2be811745f0d8032a0a9f52a33c4b2edec`, is the immutable cumulative checkpoint. All prior no-deletion charges are fixed consumed allocation: product `18,000/8,000,000` and remediation `48,000/11,000,000` gross lines/raw UTF-8 added-line bytes. Only direct linear children are charged prospectively; merges, paths outside the exact matrix, deletions, renames, copies, aliases, and unapproved ordinary files fail closed.

Fund one final `3,000/3,000,000` tranche: runtime correction/tests `1,000/1,000,000`; future H/G/Q control/evidence `2,000/2,000,000`. Product global is `21,000/11,000,000`; remediation global is `52,000/14,000,000`; source aggregate ceiling is `34,000,000`. The `115,000` hard line limit is unchanged. Future H/G/Q remains separately authorized and unexecuted.

## Validation boundary
Run targeted governance/workflow tests, type, format, and budget checks only. Do not run readiness or a full suite, Docker, KVM, AWS/provider work, or dispatch a workflow. Stop before every AWS-facing command.
