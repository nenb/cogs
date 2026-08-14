# Temporary npm audit disposition — 2026-08-03

Owner: Nick Byrne (`@nenb`)

Created: 2026-08-03T21:58:55Z

Expires: 2026-08-16T23:59:59Z

This temporary disposition is limited to three transitive package paths and nine exact advisories inside the pinned `@earendil-works/pi-coding-agent@0.80.6` development installation:

- `GHSA-3jxr-9vmj-r5cp`, `GHSA-mh99-v99m-4gvg`, and `GHSA-rgw5-rvv9-x895` at `node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion`;
- `GHSA-j3f2-48v5-ccww` at `node_modules/@earendil-works/pi-coding-agent/node_modules/protobufjs`;
- `GHSA-8xcm-r25x-g524`, `GHSA-4cwx-7wf7-3272`, `GHSA-m8rv-5g2x-5cg5`, `GHSA-jr45-8vmc-qm54`, and `GHSA-v3r7-h72x-cjcm` at `node_modules/@earendil-works/pi-coding-agent/node_modules/undici`.

Npm additionally reports `@earendil-works/pi-coding-agent` as the exact direct effect node for the nested `undici` findings. The audit checker binds that effect node, dependency edge, package path, affected range, severity, and npm-proposed replacement separately; it is not an additional advisory.

The upstream Pi package publishes an npm shrinkwrap. Root-project overrides do not replace those installed nested bytes, and Pi `0.83.0` still pins `undici` 8.5.0. On 2026-08-14, npm changed the direct affected range from `>=0.75.4` to `0.75.4 - 0.83.0` and changed its exact proposed replacement from the historical downgrade `0.75.3` to current Pi `0.84.2`. The installed Cogs dependency remains `0.80.6`; the finding set, nine advisory identities, nested package paths and bytes, severities, effect graph, and aggregate counts did not change. The checker preserves exact failure on future metadata drift and the disposition expiry is not extended. Adopting Pi `0.84.2` requires a separate compatibility, dependency-tree, image-construction, and source-closure review rather than an automatic audit fix. Cogs therefore does not claim that the ordinary development installation is fixed. CI and local development use fake or explicitly controlled test endpoints and do not constitute the production worker image or release evidence.

The production worker image does not rely on the brace-expansion or undici dispositions. Its dependency stage requires the vulnerable nested inputs to be exactly brace-expansion 5.0.6 and undici 8.5.0, obtains exact brace-expansion 5.0.9 and undici 8.9.0 from root-lock entries authenticated by registry SRI, replaces only those nested packages, and verifies both resulting versions before copying runtime bytes into the final image. Protected-main publication independently rebuilds and scans the exact digest and blocks every HIGH or CRITICAL finding, including unfixed findings.

The brace expansion code is used by Pi model-pattern matching. Cogs does not expose that pattern API: launch validation supplies one exact provider and model identifier, `src/pi/session.ts` calls exact `ModelRegistry.find`, and the runtime receives a closed resource loader instead of Pi discovery.

The protobuf finding concerns parsing `.proto` option input. Cogs supplies no `.proto` parser input to the nested Google client and does not expose such parsing to guest or campaign input. Cogs' Envoy descriptor path is separately generated, pinned, and validated outside this nested package.

The newly disclosed `fast-uri` advisory is not dispositioned. The root lock now resolves Ajv's compatible transitive dependency to fixed fast-uri 3.1.5. Npm audit no longer reports that package.

`scripts/check-npm-audit.ts` accepts only the four exact package findings, three package paths, one exact effect edge, nine advisory identities, severities, affected ranges, fix shapes, and aggregate counts above. Its 2026-08-14 metadata review changed only the exact direct Pi range and the two identical npm-proposed replacement records described above. Any additional finding, path/range/severity/effect drift, audit failure, clean upstream result, or expiry fails CI. The exception must be removed as soon as a reviewed Pi pin contains all fixes; renewal requires another security review and may not silently broaden this scope.
