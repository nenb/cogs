import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { OPENBAO_IMAGE } from "../dev/openbao-model-auth/image.ts";
import { ENVOY_IMAGE } from "../test/egress-conformance/proxy-adapters/envoy/image.ts";
import { MITMPROXY_IMAGE } from "../test/egress-conformance/proxy-adapters/mitmproxy/image.ts";

const root = resolve(import.meta.dirname, "..");
const dockerfiles = ["images/worker/Dockerfile", "images/sandbox/Dockerfile", "dev/insecure-sandbox/Dockerfile"];
for (const relativePath of dockerfiles) {
  const content = readFileSync(resolve(root, relativePath), "utf8");
  const externalStages: string[] = [];
  const stageAliases = new Set<string>();
  const instructions: Array<{ line: number; text: string }> = [];
  let logical = "";
  let logicalStart = 0;

  for (const [index, physical] of content.split("\n").entries()) {
    if (logical === "") logicalStart = index + 1;
    const continued = /\\\s*$/.test(physical);
    const fragment = continued ? physical.replace(/\\\s*$/, "") : physical;
    logical += `${logical === "" ? "" : " "}${fragment.trim()}`;
    if (!continued) {
      instructions.push({ line: logicalStart, text: logical });
      logical = "";
    }
  }
  assert.equal(logical, "", `${relativePath}:${logicalStart} has an unterminated Dockerfile instruction`);

  for (const instruction of instructions) {
    if (!/^FROM\b/i.test(instruction.text)) continue;
    const match = instruction.text.match(/^FROM(?:\s+--platform=\S+)?\s+(\S+)(?:\s+AS\s+(\S+))?\s*$/i);
    assert.ok(match, `${relativePath}:${instruction.line} has an unsupported or invalid FROM instruction`);
    const image = match[1];
    const alias = match[2]?.toLowerCase();
    assert.ok(image, `${relativePath}:${instruction.line} has an invalid FROM instruction`);
    assert.doesNotMatch(image, /\$/, `${relativePath}:${instruction.line} must not derive a base image from ARG`);

    if (image !== "scratch" && !stageAliases.has(image.toLowerCase())) externalStages.push(image);
    if (alias) stageAliases.add(alias);
  }

  assert.ok(externalStages.length > 0, `${relativePath} has no external base image`);
  for (const image of externalStages) {
    assert.match(image, /@sha256:[a-f0-9]{64}$/, `${relativePath} external base ${image} must be pinned by digest`);
    assert.doesNotMatch(image, /:latest(?:@|$)/, `${relativePath} must not use latest tags`);
  }
}

const ciWorkflow = readFileSync(resolve(root, ".github/workflows/ci.yml"), "utf8");
const kvmDriver = readFileSync(resolve(root, "dev/linux-kvm/driver.sh"), "utf8");
const kvmGitTools = readFileSync(resolve(root, "dev/linux-kvm/git-tools.sh"), "utf8");
const adr0037 = readFileSync(resolve(root, "docs/adr/0037-authorize-pinned-git-tools-disk-for-issue-71.md"), "utf8");
const envoySuite = readFileSync(resolve(root, "test/egress-conformance/proxy-adapters/envoy/suite-smoke.ts"), "utf8");
const openBaoSmoke = readFileSync(resolve(root, "dev/openbao-model-auth/ci-smoke.sh"), "utf8");
const openBaoConfig = readFileSync(resolve(root, "dev/openbao-model-auth/config.hcl"), "utf8");
const insecureContainerWorkflow = readFileSync(resolve(root, ".github/workflows/insecure-container.yml"), "utf8");
const kvmWorkflow = readFileSync(resolve(root, ".github/workflows/kvm-qualification.yml"), "utf8");
const insecureContainerDockerfile = readFileSync(resolve(root, "dev/insecure-sandbox/Dockerfile"), "utf8");
const sandboxDockerfile = readFileSync(resolve(root, "images/sandbox/Dockerfile"), "utf8");
const workerDockerfile = readFileSync(resolve(root, "images/worker/Dockerfile"), "utf8");
const nodeWorkerImage =
  "docker.io/library/node:22.22.2-bookworm-slim@sha256:9f6d5975c7dca860947d3915877f85607946403fc55349f39b4bc3688448bb6e";
const workerFinalImage =
  "gcr.io/distroless/nodejs22-debian13:nonroot@sha256:773a62fbe24a3f8c8b24b16fd59154627f8b406737bc906f83bf1732bc8907dd";
const mitmproxySuite = readFileSync(
  resolve(root, "test/egress-conformance/proxy-adapters/mitmproxy/suite-smoke.ts"),
  "utf8",
);
assert.match(ENVOY_IMAGE, /^envoyproxy\/envoy:v\d+\.\d+\.\d+@sha256:[a-f0-9]{64}$/);
assert.ok(
  ciWorkflow.includes(`ENVOY_IMAGE: ${ENVOY_IMAGE}`) || ciWorkflow.includes(`ENVOY_IMAGE: "${ENVOY_IMAGE}"`),
  "CI must scan and inventory the exact Envoy candidate pin",
);
assert.ok(
  workerDockerfile.includes(`FROM --platform=linux/amd64 ${nodeWorkerImage} AS node-runtime`),
  "worker must source exact Node 22.22.2 from the pinned Linux/amd64 stage",
);
assert.ok(
  workerDockerfile.includes(`FROM --platform=linux/amd64 ${ENVOY_IMAGE} AS envoy-runtime`),
  "worker must source the selected Envoy candidate from its exact pinned Linux/amd64 stage",
);
assert.ok(
  workerDockerfile.includes(`FROM --platform=linux/amd64 ${workerFinalImage} AS worker`),
  "worker must retain the reviewed minimal nonroot final base pin",
);
assert.match(workerDockerfile, /COPY --from=node-runtime[^\n]*\/usr\/local\/bin\/node \/nodejs\/bin\/node/u);
assert.match(workerDockerfile, /COPY --from=envoy-runtime[^\n]*\/usr\/local\/bin\/envoy \/usr\/local\/bin\/envoy/u);
assert.match(workerDockerfile, /process\.version !== 'v22\.22\.2'/u);
assert.match(workerDockerfile, /CMD \["\/opt\/cogs\/dist\/src\/main\.js"\]/u);
assert.doesNotMatch(workerDockerfile, /stage0-scaffold|production-ready="true"/u);
assert.match(MITMPROXY_IMAGE, /^mitmproxy\/mitmproxy:\d+\.\d+\.\d+@sha256:[a-f0-9]{64}$/);
assert.equal(
  OPENBAO_IMAGE,
  "quay.io/openbao/openbao:2.6.1@sha256:5b2486ab0fb90bbc788cc345b0a08616dfb375873ee8be5df3a2fd4d378a67e0",
  "retired OpenBao fixture history must retain its exact rejected digest",
);
assert.ok(
  openBaoSmoke.includes(`OPENBAO_IMAGE="${OPENBAO_IMAGE}"`),
  "retired OpenBao smoke must retain its exact historical pin",
);
assert.equal((openBaoSmoke.match(/--publish/g) ?? []).length, 1, "OpenBao smoke must publish exactly one port");
assert.ok(openBaoSmoke.includes('--publish "127.0.0.1::8200"'), "OpenBao REST API must be host-loopback-only");
assert.doesNotMatch(
  openBaoSmoke,
  /(?:--network[= ]+host|8201)/,
  "OpenBao smoke must not expose host or cluster networking",
);
assert.equal(
  openBaoConfig,
  'disable_mlock = true\napi_addr = "http://127.0.0.1:8200"\n\nstorage "file" {\n  path = "/openbao/file"\n}\n\nlistener "tcp" {\n  address = "0.0.0.0:8200"\n  tls_disable = 1\n}\n',
  "OpenBao advisory disposition requires the exact local file-storage configuration",
);
assert.doesNotMatch(
  openBaoConfig,
  /\b(?:ha_storage|cluster_addr|plugin_directory|xds)\b/i,
  "OpenBao advisory disposition forbids HA, cluster, plugin, and xDS configuration",
);
for (const workflow of [insecureContainerWorkflow, kvmWorkflow]) {
  assert.doesNotMatch(
    workflow,
    /openbao-model-auth|stage3-real-runtime|run-launcher-smoke-evidence|prepare-launcher-images/,
    "security-labelled smoke must not execute retired OpenBao-dependent paths",
  );
}
assert.ok(
  insecureContainerDockerfile.includes(
    "FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd",
  ),
  "insecure-container must use the reviewed Debian 13.6 index digest",
);
assert.ok(
  insecureContainerDockerfile.includes("ARG DEBIAN_SECURITY_SNAPSHOT=20260811T000000Z"),
  "insecure-container must use the immutable security snapshot containing fixed Expat and OpenJDK",
);
assert.ok(
  insecureContainerDockerfile.includes("libexpat1=2.8.2-1~deb13u1"),
  "insecure-container must install the exact fixed Expat package",
);
assert.ok(
  insecureContainerDockerfile.includes("openjdk-21-jre-headless=21.0.12+8-1~deb13u1"),
  "insecure-container must install the exact fixed OpenJDK package",
);
for (const label of [
  'dev.cogs.profile="insecure-container"',
  'dev.cogs.authority="functional-only"',
  'dev.cogs.package-policy="debian-trixie-snapshots-20260713-20260811-insecure-conformance-v2"',
]) {
  assert.ok(insecureContainerDockerfile.includes(label), `insecure conformance image must retain label ${label}`);
}
for (const conformanceRoot of [
  "curl",
  "dnsutils",
  "iproute2",
  "iptables",
  "netcat-openbsd",
  "nftables",
  "nodejs",
  "npm",
  "openjdk-21-jre-headless",
  "python3-httpx",
  "python3-pip",
  "python3-requests",
  "socat",
]) {
  assert.match(
    insecureContainerDockerfile,
    new RegExp(`^\\s+${conformanceRoot}(?:=[^\\s]+)?\\s+\\\\$`, "mu"),
    `insecure conformance image must retain ${conformanceRoot}`,
  );
}
for (const label of [
  'dev.cogs.profile="kata-sandbox-guest"',
  'dev.cogs.package-policy="ubuntu-noble-snapshot-20260801-production-core-v1"',
  'dev.cogs.isolation-authority="external-runtime-required"',
  'dev.cogs.credentials="proxy-capability-only-no-upstream-secrets"',
  'dev.cogs.skills-inputs="external-read-only"',
]) {
  assert.ok(sandboxDockerfile.includes(label), `sandbox image must retain label ${label}`);
}
assert.ok(
  sandboxDockerfile.includes(
    "FROM --platform=linux/amd64 ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90",
  ),
  "sandbox image must use the exact Ubuntu 24.04 OCI index and require Linux/amd64",
);
assert.equal(
  (sandboxDockerfile.match(/Snapshot: 20260801T000000Z/g) ?? []).length,
  2,
  "sandbox image must fix noble archive and security stanzas to the same Ubuntu snapshot",
);
assert.ok(
  sandboxDockerfile.includes("Suites: noble noble-updates") &&
    sandboxDockerfile.includes("Suites: noble-security") &&
    (sandboxDockerfile.match(/Components: main universe/g) ?? []).length === 2,
  "sandbox image must use only noble, noble-updates, and noble-security main+universe",
);
for (const [sha256, path] of [
  [
    "321b30ad5a1c3783cb3d73ae439f824f6d3874d76a93a62f4a984959b490aa7b",
    "pool/main/o/openssl/openssl_3.0.13-0ubuntu3.12_amd64.deb",
  ],
  [
    "6bac2a01979e210d9eac1d4d56747ec709ea60654744d66705dc3c36e7629e50",
    "pool/main/c/ca-certificates/ca-certificates_20260601~24.04.1_all.deb",
  ],
] as const) {
  assert.ok(sandboxDockerfile.includes(`ADD --checksum=sha256:${sha256}`), `bootstrap checksum ${sha256}`);
  assert.ok(
    sandboxDockerfile.includes(`https://snapshot.ubuntu.com/ubuntu/20260801T000000Z/${path}`),
    `official bootstrap URL ${path}`,
  );
}
assert.doesNotMatch(
  sandboxDockerfile,
  /rm -rf \/var\/lib\/(?:apt|dpkg)|rm -rf \/etc\/apt/,
  "sandbox image must preserve APT and dpkg metadata for scanner visibility",
);
for (const forbiddenProductionRoot of [
  "bind9-dnsutils",
  "curl",
  "iproute2",
  "iptables",
  "libexpat1",
  "netcat-openbsd",
  "nftables",
  "nodejs",
  "npm",
  "openjdk-21-jre-headless",
  "openssh-sftp-server",
  "python3-httpx",
  "python3-pip",
  "python3-requests",
  "socat",
]) {
  assert.doesNotMatch(
    sandboxDockerfile,
    new RegExp(`^\\s+${forbiddenProductionRoot}(?:=[^\\s]+)?\\s+\\\\$`, "mu"),
    `production sandbox must not request ${forbiddenProductionRoot}`,
  );
}
assert.ok(!ciWorkflow.includes("OPENBAO_IMAGE"), "retired OpenBao must not be scanned as an active CI image");
assert.ok(
  !ciWorkflow.includes("trivyignores: .trivyignore-openbao"),
  "retired OpenBao vulnerability ignore must not remain active in CI",
);
assert.equal(
  existsSync(resolve(root, ".trivyignore-openbao")),
  false,
  "retired OpenBao vulnerability ignore file must be removed",
);
assert.ok(
  !ciWorkflow.includes("openbao-model-auth.spdx.json"),
  "retired OpenBao must not receive an active selected-image SBOM job",
);
assert.ok(!ciWorkflow.includes("MITMPROXY_IMAGE"), "rejected mitmproxy must not be scanned as an active CI image");
assert.ok(
  !ciWorkflow.includes("trivyignores: .trivyignore-mitmproxy"),
  "expired candidate-only mitmproxy vulnerability ignore must not remain active in CI",
);
assert.equal(
  existsSync(resolve(root, ".trivyignore-mitmproxy")),
  false,
  "expired candidate-only mitmproxy vulnerability ignore file must be removed",
);
assert.ok(
  !ciWorkflow.includes("mitmproxy-vulnerabilities.json"),
  "rejected mitmproxy findings must not be published as an actively allowed CI image artifact",
);
assert.ok(
  !ciWorkflow.includes("mitmproxy-candidate.spdx.json"),
  "rejected mitmproxy must not receive an active selected-image SBOM job",
);
assert.match(
  kvmDriver,
  /image_url="https:\/\/cloud\.debian\.org\/images\/cloud\/trixie\/\d{8}-\d+\/\$image_name"/,
  "Linux/KVM guest image must use an immutable dated Debian release URL",
);
const guestDigest = kvmDriver.match(/image_sha512=([a-f0-9]{128})/)?.[1];
assert.ok(guestDigest, "Linux/KVM guest image must have an exact SHA-512 pin");
assert.ok(envoySuite.includes(guestDigest), "Envoy authoritative evidence must bind the exact guest image digest");
assert.ok(
  mitmproxySuite.includes(guestDigest),
  "mitmproxy authoritative evidence must bind the exact guest image digest",
);
assert.match(kvmDriver, /sha512sum --check --status/, "Linux/KVM guest image pin must be verified before boot");
assert.ok(
  adr0037.includes("debian-13-generic-amd64-20260712-2537.json") &&
    adr0037.includes("curl` is present at version `8.14.1-2+deb13u4`") &&
    adr0037.includes("but `git` is absent"),
  "ADR0037 must record the exact offline Debian manifest prerequisite finding",
);
const gitToolPins = [
  ["git", "1:2.47.3-0+deb13u1", "git_2.47.3-0+deb13u1_amd64.deb", "8861572"],
  ["libcurl3t64-gnutls", "8.14.1-2+deb13u4", "libcurl3t64-gnutls_8.14.1-2+deb13u4_amd64.deb", "384336"],
  ["libngtcp2-16", "1.11.0-1+deb13u1", "libngtcp2-16_1.11.0-1+deb13u1_amd64.deb", "131904"],
  ["libngtcp2-crypto-gnutls8", "1.11.0-1+deb13u1", "libngtcp2-crypto-gnutls8_1.11.0-1+deb13u1_amd64.deb", "29524"],
] as const;
for (const [name, version, filename, size] of gitToolPins) {
  assert.ok(
    kvmGitTools.includes(`${name}\t${version}\tamd64\t${filename}\t${size}\thttps://deb.debian.org/debian/pool/`),
  );
  assert.ok(adr0037.includes(`\`${name}\``));
  assert.ok(adr0037.includes(`\`${version}\``) && adr0037.includes(`\`${size}\``));
}
assert.match(kvmGitTools, /readonly COGS_GIT_PACKAGE_COUNT=4/, "Git tools package set must remain fixed");

console.log(
  `Verified external base-image digest pinning for ${dockerfiles.length} image definitions, exact worker Node/Envoy composition, production sandbox labels/snapshots, selected Envoy scanning, and inactive OpenBao/mitmproxy retirement.`,
);
