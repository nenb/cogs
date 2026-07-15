# Envoy ext_authz v1.38.3 descriptor assets

This directory contains the accepted ADR 0015 minimal Envoy v1.38.3 `ext_authz` descriptor inputs.

- `protos/` contains exactly the 25 extracted `.proto` files required to regenerate `envoy/service/auth/v3/external_auth.proto` with imports. It must not contain whole upstream source trees.
- `ext_authz.descriptor.pb` is generated with `protoc 33.1`, `--include_imports`, and no source info.
- `manifest.json` records source origins, hashes, descriptor metadata, loader options, and production image policy.
- Production/runtime images must include only the descriptor, manifest, and license notices; they must exclude `protos/` and `protoc`.

Runtime code must never read the source proto tree. It reads only the descriptor artifact after manifest, path, type, size, and hash verification.
