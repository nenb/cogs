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
# Pi 0.84.2's authenticated shrinkwrap contains the reviewed fixed nested
# dependencies directly. Fail closed on any package-tree drift before copying runtime bytes.
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-agent-core/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 0.84.2 \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-ai/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 0.84.2 \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-coding-agent/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 0.84.2 \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-coding-agent/node_modules/brace-expansion/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 5.0.9 \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-coding-agent/node_modules/undici/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 8.9.0 \
    && test "$(node --input-type=module --eval 'import package_ from "./node_modules/@earendil-works/pi-coding-agent/node_modules/protobufjs/package.json" with { type: "json" }; process.stdout.write(package_.version)')" = 7.6.5 \
    && rm -rf node_modules/.bin node_modules/.cache \
    && node --input-type=module --eval \
      'import { readFileSync, writeFileSync } from "node:fs"; const source = JSON.parse(readFileSync("package.json", "utf8")); const output = { name: source.name, version: source.version, private: true, type: "module", engines: { node: "22.22.2" }, dependencies: source.dependencies }; writeFileSync("package.json", `${JSON.stringify(output, null, 2)}\n`);'

FROM --platform=linux/amd64 envoyproxy/envoy:v1.38.3@sha256:5f7c43e1147412fdb3af578c651c67478a3df818eae89d2261e707e06c209cdb AS envoy-runtime

# Debian 13 distroless supplies the glibc ABI required by the selected Envoy binary
# and Node binary, but no shell, package manager, npm, or compiler.
FROM --platform=linux/amd64 gcr.io/distroless/nodejs22-debian13:nonroot@sha256:4e4fb0ce55fd73901600796ef079a9490369d2515d7da31633a91608c82ca13b AS worker
WORKDIR /opt/cogs
ENV NODE_ENV=production \
    HOME=/tmp \
    TMPDIR=/tmp \
    XDG_CACHE_HOME=/tmp/.cache

COPY --from=node-runtime --chown=0:0 --chmod=0555 /usr/local/bin/node /nodejs/bin/node
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
RUN ["/nodejs/bin/node", "--input-type=module", "--eval", "if (process.version !== 'v22.22.2') process.exit(1); const { createHash } = await import('node:crypto'); const { readFile } = await import('node:fs/promises'); const { spawnSync } = await import('node:child_process'); const envoy = await readFile('/usr/local/bin/envoy'); if (createHash('sha256').update(envoy).digest('hex') !== 'affffb8d08a14fdc375b1f7dd8d0f3004eacdf51ce07f5636d7e168a01c6b373') process.exit(1); const version = spawnSync('/usr/local/bin/envoy', ['--version'], { encoding: 'utf8' }); if (version.status !== 0 || !/(?:^|\\/)1\\.38\\.3(?:\\/|$)/.test(version.stdout)) process.exit(1); await import('/opt/cogs/dist/src/main.js');"]
