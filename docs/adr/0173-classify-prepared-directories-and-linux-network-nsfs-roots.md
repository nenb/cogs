# ADR 0173: Classify prepared directories and Linux network nsfs roots

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-25

The non-authoritative H16 private replay reached durable `NETWORK_READY` and then failed before containerd activation. Two native representations were rejected:

1. the prepared-runtime claimant called the host generation helper without an explicit kind for directory descriptors, so the helper correctly returned its conservative fallback `other`; and
2. Linux rendered the retained named network namespace mount root as `net:[4026532681]`, while the input mount census accepted only the already observed `mnt:[...]` nsfs form.

Require explicit `directory` classification for the already-open, mode-checked prepared runtime and bin descriptors. Extend only the exact nsfs namespace-root grammar to accept `mnt:[positive-decimal]` or `net:[positive-decimal]` when both filesystem type and mount source are exactly `nsfs`. Mountpoints remain absolute, malformed and other namespace prefixes remain denied, and source overlap remains denied.

H16 also demonstrated that its generic sticky `UNCERTAIN` record intentionally prevents production recovery from reinterpreting an incompletely observed cleanup. The private retained state was therefore inventoried against its durable tokenized network identities, manually removed without qualification or promotion claim, and independently checked for zero residue. This diagnostic cleanup does not alter the production sticky-uncertainty rule.

This decision grants no production fast path, retry, evidence, promotion, AWS, provider, deployment, or release authority.
