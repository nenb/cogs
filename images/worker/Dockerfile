# Production Linux/amd64 worker release candidate assembled only from pinned inputs.
# The local source build has no runtime qualification or release eligibility evidence.
FROM --platform=linux/amd64 docker.io/library/node:22.22.2-bookworm-slim@sha256:9f6d5975c7dca860947d3915877f85607946403fc55349f39b4bc3688448bb6e AS node-runtime

FROM node-runtime AS build
WORKDIR /build
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src/ ./src/
COPY schemas/integration-v1alpha1.json schemas/launch-v1alpha1.json schemas/runtime-v1alpha1.json ./schemas/
RUN npm run build --ignore-scripts

FROM node-runtime AS production-dependencies
WORKDIR /opt/cogs
COPY package.json package-lock.json ./
# Pi 0.86.0's authenticated shrinkwrap contains the reviewed fixed nested
# dependencies directly. Fail closed on any package-tree drift before copying runtime bytes.
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-agent-core/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 0.86.0 \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-ai/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 0.86.0 \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-coding-agent/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 0.86.0 \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 5.0.9 \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-coding-agent/node_modules/undici/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 8.10.2 \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-coding-agent/node_modules/protobufjs/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 7.6.6 \
    && rm -rf node_modules/.bin node_modules/.cache \
    && node --input-type=module --eval \
      'import { readFileSync, writeFileSync } from "node:fs"; const source = JSON.parse(readFileSync("package.json", "utf8")); const output = { name: source.name, version: source.version, private: true, type: "module", engines: { node: "22.22.2" }, dependencies: source.dependencies }; writeFileSync("package.json", `${JSON.stringify(output, null, 2)}\n`);'

FROM --platform=linux/amd64 docker.io/envoyproxy/envoy:distroless-v1.38.4@sha256:b28fbee81528c5b6e8857412e5e0f48ea5baa0199cf73ab611aa7f88a808eba7 AS envoy-runtime
# This complete upstream distroless source image contains no Ubuntu OpenSSL packages.
# CI scans and inventories the exact selected proxy subject before the verified Envoy
# binary is copied into the separately scanned final worker.

# Debian 13 base-nossl supplies the glibc ABI required by the selected binaries
# without the scanner-blocked OpenSSL package, shell, package manager, npm, or compiler.
FROM --platform=linux/amd64 gcr.io/distroless/base-nossl-debian13:nonroot@sha256:8c563c1fb5e120606f0d85733049775faed6192e2bd2223ef283a5393eec22b9 AS worker
WORKDIR /opt/cogs
ENV NODE_ENV=production \
    HOME=/tmp \
    TMPDIR=/tmp \
    XDG_CACHE_HOME=/tmp/.cache

COPY --from=node-runtime --chown=0:0 --chmod=0555 /usr/local/bin/node /nodejs/bin/node
# Node is OpenSSL-self-contained but dynamically requires these exact C++ runtime libraries.
COPY --from=node-runtime --chown=0:0 /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.30 /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 /usr/lib/x86_64-linux-gnu/
COPY --from=envoy-runtime --chown=0:0 --chmod=0555 /usr/local/bin/envoy /usr/local/bin/envoy
COPY --from=build --chown=65532:65532 /build/dist/ ./dist/
COPY --from=production-dependencies --chown=65532:65532 /opt/cogs/node_modules/ ./node_modules/
COPY --from=production-dependencies --chown=65532:65532 --chmod=0444 /opt/cogs/package.json ./package.json
COPY --chown=65532:65532 --chmod=0444 third_party/envoy-ext-authz-v1.38.3/ext_authz.descriptor.pb third_party/envoy-ext-authz-v1.38.3/manifest.json ./dist/third_party/envoy-ext-authz-v1.38.3/
COPY --chown=65532:65532 third_party/envoy-ext-authz-v1.38.3/LICENSES/ ./dist/third_party/envoy-ext-authz-v1.38.3/LICENSES/
COPY --chown=65532:65532 --chmod=0444 LICENSE ./licenses/cogs-Apache-2.0.txt

LABEL org.opencontainers.image.title="Cogs worker" \
      org.opencontainers.image.description="Local-source Linux/amd64 production worker release candidate" \
      org.opencontainers.image.source="https://github.com/nenb/cogs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      dev.cogs.profile="production-worker-release-candidate" \
      dev.cogs.source-kind="local-source" \
      dev.cogs.runtime-qualification="none" \
      dev.cogs.production-ready="false"

USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["/nodejs/bin/node"]
CMD ["/opt/cogs/dist/src/main.js"]

# Build-time execution in the final filesystem verifies the copied amd64 ABI,
# exact runtime versions and complete emitted import closure without starting work.
RUN ["/nodejs/bin/node", "--input-type=module", "--eval", "if (process.version !== 'v22.22.2') process.exit(1); const { createHash } = await import('node:crypto'); const { readFile } = await import('node:fs/promises'); const { spawnSync } = await import('node:child_process'); const envoy = await readFile('/usr/local/bin/envoy'); if (createHash('sha256').update(envoy).digest('hex') !== 'c994c452de131f59c9ec9f4a2fffcc65039f250a38b6279870bb95dac21db0fa') process.exit(1); const version = spawnSync('/usr/local/bin/envoy', ['--version'], { encoding: 'utf8' }); if (version.status !== 0 || !/(?:^|\\/)1\\.38\\.4(?:\\/|$)/.test(version.stdout)) process.exit(1); await import('/opt/cogs/dist/src/main.js');"]
