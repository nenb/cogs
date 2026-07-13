import assert from "node:assert/strict";
import test from "node:test";
import { MitmproxyConformanceAdapter } from "./adapter.ts";
import { MITMPROXY_IMAGE, MITMPROXY_IMAGE_DIGEST, MITMPROXY_VERSION } from "./image.ts";

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
