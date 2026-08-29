# ADR 0157: Recover interrupted runtime-download custody

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-24

A private clean static preparation on `osito` was terminated while downloading the fixed Kata archive. Process termination bypassed Python cleanup and left the exact root-created mode-0600 partial beneath the private mode-0700 immutable-preparation root. Recovery rejected it as foreign, preserving uncertainty but preventing convergence.

Recognize only the fixed partial name or its fixed removal-quarantine name for one reviewed runtime pin. Require a sole regular generation owned by the executing root custodian, mode 0600, one link, and size no greater than the reviewed archive. Retain its descriptor, quarantine and fsync before unlink, revalidate generation, unlink and fsync, and prove link count zero. Duplicate, replacement, changed-policy, oversized, symlink, or foreign names remain preserved failures. Recovery is restartable when an earlier aggregated attempt already removed the transaction-created empty artifact cache: absence is accepted only when durable custody proves the root/cache were created by this transaction with no baseline or retained sentinel; an exact empty surviving root is removed and fsynced. This cleanup never adopts partial bytes or resumes a download.

No retry, evidence, AWS, provider, deployment, promotion, or release authority follows.
