import assert from "node:assert/strict";
import test from "node:test";
import { validateManifest } from "../controller/runner.ts";
import { STAGE_1_CASES, STAGE_1_MANIFEST } from "./stage-1.ts";

test("Stage 1 manifest is immutable, schema-valid, complete by required group, and control-linked", () => {
  validateManifest(STAGE_1_MANIFEST);
  assert.equal(Object.isFrozen(STAGE_1_MANIFEST), true);
  assert.equal(Object.isFrozen(STAGE_1_MANIFEST.cases), true);
  assert.equal(new Set(STAGE_1_CASES.map((item) => item.id)).size, STAGE_1_CASES.length);
  assert.deepEqual(
    new Set(STAGE_1_CASES.map((item) => item.group)),
    new Set([
      "identity-route",
      "http-parsing",
      "credential-handling",
      "bypass-resistance",
      "audit-failure",
      "revocation",
    ]),
  );
  const byId = new Map(STAGE_1_CASES.map((item) => [item.id, item]));
  for (const item of STAGE_1_CASES) {
    const controlId = item.probe.positiveControl;
    if (item.probe.expected === "deny" || item.probe.expected === "safe")
      assert.ok(controlId, `${item.id} must name its positive control`);
    if (controlId) {
      const control = byId.get(controlId);
      assert.ok(control, `${item.id} references an unknown positive control`);
      assert.equal(control.probe.expected, "allow", `${item.id} control must permit its declared behavior`);
    }
  }
});

test("Stage 1 case metadata covers every mandatory parser and credential behavior", () => {
  const scenarios = new Set(STAGE_1_CASES.map((item) => item.probe.scenario));
  for (const required of [
    "cl-te-conflict",
    "duplicate-host",
    "duplicate-authorization",
    "duplicate-proxy-authorization",
    "ambiguous-whitespace",
    "obs-fold",
    "oversized-header",
    "oversized-request-line",
    "invalid-chunk-size",
    "invalid-chunk-extension",
    "duplicate-pseudo",
    "reordered-pseudo",
    "invalid-pseudo",
    "downgrade-ambiguity",
    "bearer",
    "api-key",
    "basic",
    "all-sinks",
    "long-lived-drain",
    "unset-proxy",
    "direct-ipv4",
    "direct-ipv6",
    "arbitrary-dns",
    "dns-over-https",
    "udp-quic",
    "nested-connect",
    "websocket",
    "proxy-admin",
    "cloud-metadata",
  ])
    assert.ok(scenarios.has(required), `missing mandatory scenario ${required}`);
});
