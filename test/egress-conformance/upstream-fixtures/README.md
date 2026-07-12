# Upstream fixtures

These fixtures are trusted test-controller components. They provide HTTP/1.1 and HTTP/2 over an ephemeral TLS hierarchy, protected bearer/API-key/Basic endpoints, redirects, bounded large and streaming responses, delayed responses for drain/revocation tests, and silent TCP/UDP denial sensors.

Security rules:

- Expected credentials are converted immediately to keyed digests; request handlers do not retain plaintext expected values.
- Received credential values are compared in memory and reduced to `credential_present` and `credential_matches` booleans.
- Responses and observations never contain credential values, request bodies, query strings, raw authorities, payloads, or peer addresses.
- Raw authorities are reduced to presence and an optional expected-authority comparison.
- TCP and UDP listeners never respond. Sticky reachability observations cannot be displaced by HTTP observation capacity.
- TLS private-key files are generated in a temporary directory and removed before the fixture starts serving. In-memory leaf-key material is cleared after the TLS context is created.
- Request concurrency, response sizes, stream lengths, delays, and observation storage are bounded.
- `stop()` is idempotent, aborts delayed/streaming work, destroys open sockets, applies a teardown deadline, and clears keyed credential digests.

These sensors are positive controls. A connection reaching either denial listener means external network enforcement failed; listener reachability itself is never a successful security result.
