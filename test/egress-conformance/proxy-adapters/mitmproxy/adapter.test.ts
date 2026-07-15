import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { MitmproxyConformanceAdapter } from "./adapter.ts";
import { MITMPROXY_IMAGE, MITMPROXY_IMAGE_DIGEST, MITMPROXY_VERSION } from "./image.ts";

const root = resolve(import.meta.dirname, "../../../..");

test("mitmproxy retired exception is not active CI policy", () => {
  const ci = readFileSync(resolve(root, ".github/workflows/ci.yml"), "utf8");
  const insecure = readFileSync(resolve(root, ".github/workflows/insecure-container.yml"), "utf8");
  const kvm = readFileSync(resolve(root, ".github/workflows/kvm-qualification.yml"), "utf8");
  const retirement = readFileSync(resolve(root, "docs/security-evidence/mitmproxy-12.2.3-retirement.md"), "utf8");
  const adr = readFileSync(resolve(root, "docs/adr/0011-select-envoy-for-http-egress.md"), "utf8");
  assert.equal(existsSync(resolve(root, ".trivyignore-mitmproxy")), false);
  assert.doesNotMatch(
    ci,
    /MITMPROXY_IMAGE|trivyignores: \.trivyignore-mitmproxy|mitmproxy-candidate\.spdx|mitmproxy-vulnerabilities/,
  );
  assert.doesNotMatch(insecure + kvm, /proxy-adapters\/mitmproxy\/.*suite-smoke|proxy-adapters\/mitmproxy\/.*ci-smoke/);
  assert.match(retirement, /six unique HIGH finding identifiers/);
  assert.match(retirement, /eight package records/);
  for (const id of [
    "CVE-2026-4878",
    "CVE-2026-45447",
    "GHSA-537c-gmf6-5ccf",
    "GHSA-6v7p-g79w-8964",
    "CVE-2026-49853",
    "CVE-2026-49855",
  ]) {
    assert.match(retirement, new RegExp(id));
  }
  assert.match(retirement + adr, /not an active Stage 3 path/);
  assert.match(retirement + adr, /not (?:a )?release fallback/);
  assert.match(adr, /Envoy/);
});

test("mitmproxy candidate identity is exact and adapter rejects unsafe bounds", () => {
  assert.equal(MITMPROXY_IMAGE, `mitmproxy/mitmproxy:${MITMPROXY_VERSION}@${MITMPROXY_IMAGE_DIGEST}`);
  assert.match(MITMPROXY_VERSION, /^\d+\.\d+\.\d+$/);
  assert.match(MITMPROXY_IMAGE_DIGEST, /^sha256:[a-f0-9]{64}$/);
  assert.throws(
    () =>
      new MitmproxyConformanceAdapter({
        listenerPort: 80,
        upstreamCaCertificatePem: "fixture",
        policyFor: async () => {
          throw new Error("not reached");
        },
        commandFor: () => ({ command: "false", args: [] }),
      }),
  );
});
