# ADR 0174: Install reviewed tool policy before recovery journal parse

- Status: Accepted under the owner's explicit standing authorization for all non-AWS prerequisite work
- Date: 2026-08-25

Native H16/H17 recovery exposed an ordering cycle. Every admitted command record is validated against the identity-sealed reviewed host-tool policy map. Fresh execution installs that map when it issues retained executable ownership, but cleanup-only recovery attempted to parse the journal before issuing any static executable owner. A valid admitted journal therefore classified as `preserve` solely because the expected policy entry was absent.

During cleanup-only entry, issue the complete retained executable owner from already validated static custody before opening the existing operation. This installs immutable hash/path/closure policy data but claims no tool and performs no mutation. After exact journal parsing, the existing reconstruction boundary independently binds the journal source revision and source-manifest digest to static custody before any cleanup role can be claimed. Reuse that same owner rather than replacing it with an empty static marker owner.

The H17 diagnostic also correctly rejected a private `/run/netns` self-bind retained by the manually settled H16 failure. H17 admitted no tokenized network mutation. Its exact support-directory identities and fixed roots were inventoried and privately removed, the older self-bind was unmounted, and independent residue checking passed. This grants neither H16 nor H17 qualification authority.

This correction preserves sticky uncertainty and the existing rule that reconstruction failure performs no teardown. It grants no retry, production fast path, evidence, promotion, AWS, provider, deployment, or release authority.
