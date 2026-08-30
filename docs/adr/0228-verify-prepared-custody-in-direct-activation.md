# ADR 0228: Verify prepared custody in direct activation

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

H71 showed that the sole prepared claim was consumed but lacked the independently recorded `verified` transition required by ADR 0227. The legacy `prestage_runtime.retain` path consumes and verifies the claim, but the production direct `_activate_prepared_containerd` path durably recorded consumption and then staged it without invoking the static-custody verification transition.

In the direct activation path, after the prepared facts are durably recorded and the claim is consumed, independently reopen and verify the prepared pathname against the retained claim before any runtime stage intent or mutation. This preserves the existing write-ahead order while ensuring that final retirement can prove the consumed source was checked immediately before effects. Verification failure occurs before mutation and remains cleanup-only recoverable; no missing or reconstructed claim is accepted.

Focused admission, runtime hostile, mutable-bridge, coordinator, TypeScript, formatting, and retained-line matrices pass. H71 remains a private non-authoritative diagnostic and minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
