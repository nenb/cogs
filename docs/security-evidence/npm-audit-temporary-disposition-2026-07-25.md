# Temporary npm audit disposition — 2026-07-25

Owner: Nick Byrne (`@nenb`)

Created: 2026-07-25T01:40:00Z

Expires: 2026-08-08T01:39:59Z

This temporary disposition is limited to two transitive findings inside the pinned `@earendil-works/pi-coding-agent@0.80.6` package:

- `GHSA-mh99-v99m-4gvg` at `node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion`;
- `GHSA-j3f2-48v5-ccww` at `node_modules/@earendil-works/pi-coding-agent/node_modules/protobufjs`.

The upstream Pi package publishes an npm shrinkwrap. Root-project overrides do not replace those installed nested bytes, and no current Pi release contains fixes for both findings. Cogs therefore does not claim that the installed versions are fixed.

On 2026-07-31 npm revised the existing brace-expansion advisory metadata from source `1124334` / range `<=5.0.7` to source `1130591` / range `>=4.0.0 <5.0.8`, without changing the advisory URL, severity, installed dependency path, affected installed version, or disposition scope. The exact audit gate was updated to the revised metadata; this narrows rather than broadens the affected range.

The affected brace expansion is used by Pi model-pattern matching. Cogs does not expose that pattern API: launch validation supplies one exact provider and model identifier, `src/pi/session.ts` calls exact `ModelRegistry.find`, and the runtime receives a closed resource loader instead of Pi discovery. Guest or campaign input cannot invoke Pi model glob selection.

The protobuf finding concerns parsing `.proto` option input. Cogs supplies no `.proto` parser input to the nested Google client and does not expose such parsing to guest or campaign input. Cogs' Envoy descriptor path is separately generated, pinned, and validated outside this nested package.

`scripts/check-npm-audit.ts` accepts only the two exact advisory identities, severities, affected ranges, and dependency paths above. Any additional finding, path/range/severity drift, audit failure, clean upstream result, or expiry fails CI. The exception must be removed as soon as a reviewed Pi pin contains both fixes; renewal requires another security review and may not silently broaden this scope.
