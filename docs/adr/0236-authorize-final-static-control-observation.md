# ADR 0236: Authorize the final static-control observation

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-29

Freeze implementation H as `dfb28c2e8deb7fed90da095c41b4d556c737af97` after the complete final local suite. H includes the accepted cached and production-fsync private gates, fail-closed private strict-fresh observations, and focused recovery corrections through ADR 0235.

Authorize exactly one independently dispatched no-KVM static-control observation G for that earlier H. Guard v21 preserves the complete authenticated predecessor history through successful run 32633570406, workflow head `c16f3168a2b14ed0b88acf5753ef106940af1b73`, and reviewed H `892c3fc44e37d74792fe552107839b920ea98e8e`. Every outcome consumes the observation; failure, cancellation, missing artifact, or drift grants no retry or claim.

G describes H and may not alter it. This authorization is GitHub/local qualification work only. It grants no AWS, provider, deployment, campaign, production, release, or promotion authority.
