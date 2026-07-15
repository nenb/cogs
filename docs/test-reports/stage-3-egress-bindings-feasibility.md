# Stage 3 egress bindings feasibility

Date: 2026-07-15

This read-only spike evaluated the ADR 0015 Envoy `ext_authz` dependency/binding strategy. It used only `/tmp` work directories. It made no repository, package, PR, Docker, or AWS changes.

## Inputs inspected

### npm packages

Metadata and tarballs were inspected with lifecycle scripts disabled.

| Package | Role | License | Registry integrity | Tarball SHA-512 |
|---|---|---|---|---|
| `@grpc/grpc-js@1.14.4` | gRPC server runtime | Apache-2.0 | `sha512-k9Dj3DV/itK9D06Y8f190Qgop7/Ui+D0njFV3LHMPwPT75DpXLQohE9Wmz0QElrJnzsjB7KPWiKJbOl7IPDArQ==` | `93d0e3dc357f8ad2bd0f4e98f1fd7dd10828a7bfd48be0f49e3155dcb1cc3f03d3ef90e95cb428844f569b3d10125ac99f3b2307b28f5a22896ce97b20f0c0ad` |
| `@grpc/proto-loader@0.8.1` | candidate dynamic trusted proto loader | Apache-2.0 | `sha512-wtF6h+DY6M3YaDBPAmvuuA6jV8Sif9MjtOI5euKFWRgCDl5PeDpPsHR9u2l6St5ceY8AZgoNDww5+HvEsXFsGg==` | `c2d17a87e0d8e8cdd868304f026beeb80ea357c4a27fd323b4e2397ae2855918020e5e4f783a4fb0747dbb697a4ade5c798f00660a0d0f0c39f87bc4b1716c1a` |
| `ts-proto@2.12.0` | static-generation measurement candidate | ISC | `sha512-ezMxg57ZiK/ZTW14U7y38+qyWHJr8cn8ELKuppANER666YnUteuNFO/mM1qI+9/wAHoTAfRadnIwtVdp1xw0jQ==` | `7b3331839ed988afd94d6d7853bcb7f3eab258726bf1c9fc10b2aea6900d111ebae989d4b5eb8d14efe6335a88fbdff0007a1301f45a767230b55769d71c348d` |

Observed runtime transitive licenses for the dynamic path are compatible-looking pending normal lock/license checks: Apache-2.0, MIT, BSD-3-Clause, and ISC packages through the existing npm lock graph.

### Envoy and external proto sources

Root proto: `envoy/service/auth/v3/external_auth.proto` from Envoy v1.38.3.

| Source | URL | Declared integrity | Downloaded SHA-256 |
|---|---|---|---|
| Envoy v1.38.3 archive | `https://github.com/envoyproxy/envoy/archive/refs/tags/v1.38.3.tar.gz` | n/a | `db23fed5e174e7988e4b0eaf7718cd3c33230f334bb3fa458e90549a506a8944` |
| BCR `googleapis@0.0.0-20251003-2193a2bf` | `https://github.com/googleapis/googleapis/archive/2193a2bfcecb92b92aad7a4d81baa428cafd7dfd.zip` | `sha256-B6b3AM7lynlvUjCHbthFS/HYzECbOz5jRQW8TzKp9ys=` | `07a6f700cee5ca796f5230876ed8454bf1d8cc409b3b3e634505bc4f32a9f72b` |
| BCR `protobuf@33.1` | `https://github.com/protocolbuffers/protobuf/releases/download/v33.1/protobuf-33.1.tar.gz` | `sha256-/aEyywyGQAOBwK8f6YvQ93XLVmyyR83MEF40TgCsww4=` | `fda132cb0c86400381c0af1fe98bd0f775cb566cb247cdcc105e344e00acc30e` |
| BCR `protoc-gen-validate@1.2.1.bcr.2` | `https://github.com/bufbuild/protoc-gen-validate/archive/refs/tags/v1.2.1.tar.gz` | `sha256-5HGDUnVN8Tk7h5K2MTOKqFYvOQ6BYHg+NlRUvBHZYyg=` | `e4718352754df1393b8792b631338aa8562f390e8160783e365454bc11d96328` |
| BCR `xds@0.0.0-20240423-555b57e` | `https://github.com/cncf/xds/archive/555b57ec207be86f811fb0c04752db6f85e3d7e2.tar.gz` | `sha256-DIxPD2f+2We1EEn31eLKepvUM5cKKciOJyyGZTKBcvU=` | `0c8c4f0f67fed967b51049f7d5e2ca7a9bd433970a29c88e272c8665328172f5` |

The Envoy-owned import closure resolved to 12 proto files and 1,826 proto source lines before external imports. The full minimal official closure also requires Google protobuf WKTs, `google/rpc/status.proto`, UDPA annotations, XDS context params, and `validate/validate.proto` from the BCR-pinned sources above.

## Option B static-generation measurement

`protoc 29.3` was used only as a disclosed measurement tool and is **not** an accepted production build pin.

Candidate run: `ts-proto@2.12.0` against the full minimal official ext_authz closure, with grpc-js service definitions and NodeNext-compatible import suffixes. No reduced custom proto was invented.

Options used for the leanest successful measurement:

```text
outputServices=grpc-js,esModuleInterop=true,forceLong=string,oneof=unions,env=node,
outputJsonMethods=false,outputPartialMethods=false,outputClientImpl=false,
outputTypeAnnotations=false,unrecognizedEnum=false,importSuffix=.js,
comments=false,exportCommonSymbols=false,outputExtensions=false
```

Measured output:

| Metric | Value |
|---|---:|
| Generated TypeScript files | 25 |
| Generated TypeScript lines | 12,864 |
| Generated TypeScript bytes | 352,756 |
| Runtime imports | `@bufbuild/protobuf/wire` in 24 files; `@grpc/grpc-js` in 1 file |

Validation in `/tmp`:

- TypeScript 5.9.3 strict NodeNext typecheck passed.
- Emitted JavaScript roundtripped an empty `CheckRequest` and an OK `CheckResponse` under Node.

## Conclusion

Static generated TypeScript is technically feasible, but the leanest measured official closure is 12,864 generated `src`-countable lines before Cogs authorization, WAL, OpenBao, and lifecycle code. That exceeds ADR 0015's 450-line binding bucket and would breach the proposed 8,500-line aggregate cap.

The selected issue #66 strategy should therefore use the dynamic trusted-input path: exact `@grpc/grpc-js@1.14.4` plus exact `@grpc/proto-loader@0.8.1`, with the exact official Envoy v1.38.3 and BCR-pinned external proto closure vendored as non-`src` trusted assets, hash/import checked before readiness, and loaded only once from immutable trusted paths. This accepts runtime schema parsing only for pinned trusted startup inputs; request decoding still uses generated protobufjs service mappings, and Cogs maps only the required own fields into its narrow authorization envelope.
