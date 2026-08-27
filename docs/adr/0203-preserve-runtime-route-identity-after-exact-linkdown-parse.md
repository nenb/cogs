# ADR 0203: Preserve runtime route identity after exact linkdown parse

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-27

H48 accepted the exact teardown-only TAP `linkdown` routes, then correctly rejected the newly hashed raw route bytes as a replacement of the retained runtime identity. After the complete teardown route inventory is parsed against the exact linkdown contract, retain the prior route identity digest. This treats linkdown as the already-validated retirement state of the same routes rather than a new route identity.

No raw bytes bypass validation: every route and flag is parsed first, and any other change remains a replacement. Forward runtime route hashing is unchanged. H48 and its uncertain cleanup state were preserved before exact diagnostic cleanup. It minted no qualification.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
