# Temporary npm audit disposition — 2026-08-03

Owner: Nick Byrne (`@nenb`)

Created: 2026-08-03T17:33:04Z

Expires: 2026-08-16T23:59:59Z

This temporary disposition is limited to two transitive package paths and four exact advisories inside the pinned `@earendil-works/pi-coding-agent@0.80.6` development/runtime dependency:

- `GHSA-3jxr-9vmj-r5cp`, `GHSA-mh99-v99m-4gvg`, and `GHSA-rgw5-rvv9-x895` at `node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion`;
- `GHSA-j3f2-48v5-ccww` at `node_modules/@earendil-works/pi-coding-agent/node_modules/protobufjs`.

The upstream Pi package publishes an npm shrinkwrap. Root-project overrides do not replace those installed nested bytes, and the current reviewed Pi line does not contain fixes for all four advisories. Cogs therefore does not claim that the ordinary development installation is fixed.

The affected brace expansion is used by Pi model-pattern matching. Cogs does not expose that pattern API: launch validation supplies one exact provider and model identifier, `src/pi/session.ts` calls exact `ModelRegistry.find`, and the runtime receives a closed resource loader instead of Pi discovery. Guest or campaign input cannot invoke Pi model glob selection.

The production worker image does not rely on this disposition. Its dependency stage requires the vulnerable nested input to be exactly 5.0.6, obtains exact `brace-expansion` 5.0.9 from the root lock with registry SRI, replaces the nested package, verifies the resulting nested version, and copies only that remediated tree into the final image. A local all-severity Trivy scan using the release workflow's pinned Trivy image and database found zero HIGH or CRITICAL findings after this replacement. Protected-main publication independently rebuilds and scans the exact digest and blocks every HIGH or CRITICAL finding, including unfixed findings.

The protobuf finding concerns parsing `.proto` option input. Cogs supplies no `.proto` parser input to the nested Google client and does not expose such parsing to guest or campaign input. Cogs' Envoy descriptor path is separately generated, pinned, and validated outside this nested package.

`scripts/check-npm-audit.ts` accepts only the two exact package paths, four advisory identities, severities, affected ranges, and aggregate counts above. Any additional finding, path/range/severity drift, audit failure, clean upstream result, or expiry fails CI. The exception must be removed as soon as a reviewed Pi pin contains all fixes; renewal requires another security review and may not silently broaden this scope.
