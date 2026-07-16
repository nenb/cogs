import { readFile } from "node:fs/promises";

process.env.COGS_SOURCE_REVISION ??= "a".repeat(40);
process.env.COGS_OPENBAO_ADDR ??= "http://127.0.0.1:8200";
process.env.COGS_ENVOY_EXECUTABLE ??= "/tmp/envoy";
process.env.COGS_ENVOY_IMAGE ??= `envoyproxy/envoy:v1.38.3@sha256:${"b".repeat(64)}`;
process.env.COGS_ENVOY_IMAGE_DIGEST ??= `sha256:${"b".repeat(64)}`;
process.env.COGS_OPENBAO_IMAGE ??= `quay.io/openbao/openbao:2.6.0@sha256:${"d".repeat(64)}`;
process.env.COGS_OPENBAO_RUNTIME_VERSION ??= "OpenBao v2.6.0";
process.env.COGS_TRUST_CERT_PATH ??= "/usr/local/share/ca-certificates/cogs-stage3-real-runtime.crt";

const harness: { assertValidRealRuntimeSidecar(value: unknown): void } = await import(
  "../test/egress-conformance/stage3-real-runtime/harness.ts"
);

const paths = process.argv.slice(2);
if (paths.length === 0) throw new Error("no Stage 3 real-runtime sidecars provided");
for (const path of paths) harness.assertValidRealRuntimeSidecar(JSON.parse(await readFile(path, "utf8")));
