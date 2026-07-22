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
const openBaoIgnore = readFileSync(resolve(root, ".trivyignore-openbao"), "utf8");
const insecureContainerWorkflow = readFileSync(resolve(root, ".github/workflows/insecure-container.yml"), "utf8");
const mitmproxySuite = readFileSync(
  resolve(root, "test/egress-conformance/proxy-adapters/mitmproxy/suite-smoke.ts"),
  "utf8",
);
assert.match(ENVOY_IMAGE, /^envoyproxy\/envoy:v\d+\.\d+\.\d+@sha256:[a-f0-9]{64}$/);
assert.ok(
  ciWorkflow.includes(`ENVOY_IMAGE: ${ENVOY_IMAGE}`),
  "CI must scan and inventory the exact Envoy candidate pin",
);
assert.match(MITMPROXY_IMAGE, /^mitmproxy\/mitmproxy:\d+\.\d+\.\d+@sha256:[a-f0-9]{64}$/);
assert.equal(
  OPENBAO_IMAGE,
  "quay.io/openbao/openbao:2.6.0@sha256:900bb64d0671cd1d82b693c56206f7263b582445f3a3bb6ba6e5213f524a6653",
  "OpenBao model-auth smoke must use the accepted v2.6.0 digest",
);
assert.ok(ciWorkflow.includes(`OPENBAO_IMAGE: ${OPENBAO_IMAGE}`), "CI must scan and inventory the exact OpenBao pin");
const openBaoScan = ciWorkflow.match(
  / {6}- name: Scan pinned OpenBao model-auth fixture\n[\s\S]*?(?=\n {6}- name:)/,
)?.[0];
assert.ok(openBaoScan, "CI must Trivy-scan the OpenBao pin");
assert.match(openBaoScan, /image-ref: \$\{\{ env\.OPENBAO_IMAGE \}\}/, "OpenBao scan must use the exact pinned image");
assert.ok(openBaoScan.includes('exit-code: "1"'), "OpenBao scan must fail on findings");
assert.ok(openBaoScan.includes("severity: HIGH,CRITICAL"), "OpenBao scan must retain its severity boundary");
assert.ok(openBaoScan.includes("trivyignores: .trivyignore-openbao"), "OpenBao scan must use its scoped ignore file");
assert.equal(
  (ciWorkflow.match(/trivyignores: \.trivyignore-openbao/g) ?? []).length,
  1,
  "OpenBao Trivy ignore file must be wired exactly once",
);
assert.ok(ciWorkflow.includes("openbao-model-auth.spdx.json"), "CI must generate an OpenBao model-auth fixture SBOM");
assert.ok(openBaoSmoke.includes(`OPENBAO_IMAGE="${OPENBAO_IMAGE}"`), "OpenBao smoke must run the exact scanned pin");
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
assert.ok(
  insecureContainerWorkflow.includes("dev/openbao-model-auth/ci-smoke.sh"),
  "security-labelled smoke must run OpenBao model-auth fixture",
);
assert.ok(openBaoIgnore.includes("review deadline 2026-08-15"), "OpenBao CVE ignores must carry their review deadline");
assert.equal(openBaoIgnore.includes("CVE-2026-39822"), false, "OpenBao ignore must not suppress Go stdlib CVE");
assert.deepEqual(
  openBaoIgnore
    .split(/\r?\n/)
    .filter((line) => line.startsWith("CVE-"))
    .sort(),
  ["CVE-2024-8185", "CVE-2024-9180", "CVE-2025-59043", "CVE-2025-64761", "CVE-2026-45808"],
  "OpenBao Trivy ignore must contain only reviewed pseudo-module CVE false positives",
);
assert.deepEqual(
  openBaoIgnore.split(/\r?\n/).filter((line) => line.startsWith("GHSA-")),
  ["GHSA-hrxh-6v49-42gf"],
  "OpenBao Trivy ignore must contain exactly the reviewed grpc-go advisory",
);
assert.ok(openBaoIgnore.includes("real grpc-go v1.81.1 finding"), "grpc-go disposition must identify a real finding");
assert.ok(
  openBaoIgnore.includes("sha256:900bb64d0671cd1d82b693c56206f7263b582445f3a3bb6ba6e5213f524a6653"),
  "grpc-go disposition must bind the exact OpenBao digest",
);
assert.ok(
  openBaoIgnore.includes("file storage; no HA, xDS, cluster forwarding, or external plugins; host-loopback-only REST"),
  "grpc-go disposition must state the complete fixed fixture boundary",
);
assert.ok(openBaoIgnore.includes("Any boundary or image drift invalidates"), "grpc-go disposition must fail on drift");
const grpcIgnoreDeadline = "2026-07-29T23:59:59Z";
assert.ok(
  openBaoIgnore.includes(`Hard expiry: ${grpcIgnoreDeadline}`),
  "grpc-go disposition must state its hard expiry",
);
assert.ok(
  Date.now() <= Date.parse(grpcIgnoreDeadline),
  "grpc-go scan exception expired; remove it or record a new decision",
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
  `Verified external base-image digest pinning for ${dockerfiles.length} image definitions, selected Envoy/OpenBao scanning, and inactive mitmproxy exception removal.`,
);
