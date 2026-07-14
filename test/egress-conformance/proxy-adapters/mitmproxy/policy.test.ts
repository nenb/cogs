import assert from "node:assert/strict";
import test from "node:test";
import { type MitmproxyPolicyInput, renderMitmproxyPolicy } from "./policy.ts";

const input = (): MitmproxyPolicyInput => ({
  caseId: "mitmproxy.case",
  sessionId: "session.case",
  authorizationOrigin: "http://127.0.0.1:43123",
  routes: [
    {
      id: "route.bearer",
      protocol: "https",
      host: "localhost",
      port: 443,
      methods: ["GET"],
      pathPrefix: "/protected/header",
      query: "service=git-upload-pack",
      credential: { kind: "bearer", value: "Bearer fixture-value" },
    },
    {
      id: "route.api",
      protocol: "https",
      host: "api.example.test",
      port: 8443,
      methods: ["POST"],
      pathPrefix: "/v1/",
      credential: { kind: "api-key", header: "x-api-key", value: "fixture-api-value" },
    },
    {
      id: "route.basic",
      protocol: "https",
      host: "basic.example.test",
      port: 443,
      methods: ["GET"],
      pathPrefix: "/",
      credential: { kind: "basic", value: "Basic Zml4dHVyZTpwYXNzd29yZA==" },
    },
  ],
});

test("mitmproxy policy is deterministic, exact, and supports all credential forms", () => {
  const rendered = renderMitmproxyPolicy(input());
  assert.equal(rendered, renderMitmproxyPolicy({ ...input(), routes: [...input().routes].reverse() }));
  const policy = JSON.parse(rendered) as Record<string, unknown>;
  assert.equal(policy.version, "cogs.mitmproxy-policy/v1alpha1");
  assert.match(rendered, /Bearer fixture-value/);
  assert.match(rendered, /Basic Zml4dHVyZTpwYXNzd29yZA==/);
  assert.match(rendered, /x-api-key/);
  assert.match(rendered, /service=git-upload-pack/);
  assert.doesNotMatch(rendered, /admin|password|private_key/);
});

test("mitmproxy policy rejects ambiguous or credential-bearing control input", () => {
  assert.throws(() => renderMitmproxyPolicy({ ...input(), authorizationOrigin: "http://user@127.0.0.1:43123" }));
  assert.throws(() =>
    renderMitmproxyPolicy({
      ...input(),
      routes: [...input().routes, structuredClone(input().routes[0] as object) as never],
    }),
  );
  const malformed = structuredClone(input());
  assert.ok(malformed.routes[0]);
  malformed.routes[0].pathPrefix = "/protected/%2e%2e/";
  assert.throws(() => renderMitmproxyPolicy(malformed));
  const malformedQuery = structuredClone(input());
  assert.ok(malformedQuery.routes[0]);
  malformedQuery.routes[0].query = "token=secret&extra=true";
  assert.throws(() => renderMitmproxyPolicy(malformedQuery));
  const unsafe = structuredClone(input());
  assert.ok(unsafe.routes[1]);
  unsafe.routes[1].credential = { kind: "api-key", header: "authorization", value: "fixture" };
  assert.throws(() => renderMitmproxyPolicy(unsafe));
});
