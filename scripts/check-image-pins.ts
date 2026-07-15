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
const envoySuite = readFileSync(resolve(root, "test/egress-conformance/proxy-adapters/envoy/suite-smoke.ts"), "utf8");
const openBaoSmoke = readFileSync(resolve(root, "dev/openbao-model-auth/ci-smoke.sh"), "utf8");
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
assert.ok(ciWorkflow.includes("Scan pinned OpenBao model-auth fixture"), "CI must Trivy-scan the OpenBao pin");
assert.equal(
  (ciWorkflow.match(/trivyignores: \.trivyignore-openbao/g) ?? []).length,
  1,
  "OpenBao Trivy ignore file must be wired exactly once",
);
assert.ok(ciWorkflow.includes("openbao-model-auth.spdx.json"), "CI must generate an OpenBao model-auth fixture SBOM");
assert.ok(openBaoSmoke.includes(`OPENBAO_IMAGE="${OPENBAO_IMAGE}"`), "OpenBao smoke must run the exact scanned pin");
assert.ok(
  insecureContainerWorkflow.includes("dev/openbao-model-auth/ci-smoke.sh"),
  "security-labelled smoke must run OpenBao model-auth fixture",
);
assert.ok(openBaoIgnore.includes("review deadline 2026-08-15"), "OpenBao Trivy ignore must carry review deadline");
assert.equal(openBaoIgnore.includes("CVE-2026-39822"), false, "OpenBao ignore must not suppress Go stdlib CVE");
assert.deepEqual(
  openBaoIgnore
    .split(/\r?\n/)
    .filter((line) => line.startsWith("CVE-"))
    .sort(),
  ["CVE-2024-8185", "CVE-2024-9180", "CVE-2025-59043", "CVE-2025-64761", "CVE-2026-45808"],
  "OpenBao Trivy ignore must contain only reviewed pseudo-module false positives",
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

console.log(
  `Verified external base-image digest pinning for ${dockerfiles.length} image definitions, selected Envoy/OpenBao scanning, and inactive mitmproxy exception removal.`,
);
