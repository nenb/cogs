# ADR 0226: Retire revalidated static-source descriptors

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-28

The H69 `runtime` marker also covers descriptors retained by complete static-source verification, because the reviewed source manifest includes the immutable prepared `kata-runtime-v1` source tree. Those descriptors are separate from the prepared-runtime claim addressed by ADR 0225. Replaying without accounting for this known owner would be blind.

Record the descriptors opened solely by complete-source verification. At the post-final-baseline retirement boundary, rerun the complete bounded source verification against the already authenticated implementation manifest using fresh temporary descriptors, close that temporary observation, then require every original source-verification descriptor and the source anchor to be unique members of static custody. Retire and close those originals with the other consumed runtime-related custody. Final source approval remains bound to the authenticated in-memory envelope. Changed, incomplete, foreign, duplicate, unstable, or uncloseable source custody fails closed; whole-custody abort cannot double-close retired descriptors.

Focused admission, mutable-bridge, coordinator, TypeScript, formatting, and retained-line matrices pass. This is an inventory correction from H69, not qualification evidence.

This grants no AWS, provider, deployment, campaign, production, release, or qualification authority.
