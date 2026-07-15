import assert from "node:assert/strict";
import { test } from "node:test";
import { buildExtAuthzResponse, ExtAuthzAdapterError, parseExtAuthzCheck } from "../src/egress/ext-authz-adapter.ts";
import { loadExtAuthzDescriptor } from "../src/egress/ext-authz-descriptor.ts";

const context = [
  { key: "cogs.mode", value: "authorize" },
  { key: "cogs.case_id", value: "case-a" },
  { key: "cogs.session_id", value: "session-a" },
  { key: "cogs.route_id", value: "route-a" },
  { key: "cogs.require_capability", value: "true" },
  { key: "cogs.credential_required", value: "true" },
];

function request(overrides: Partial<Record<string, unknown>> = {}): unknown {
  return {
    attributes: {
      context_extensions: context,
      request: {
        http: {
          headers: [{ key: "proxy-authorization", value: "capability" }],
          method: "GET",
          host: "example.com",
          path: "/allowed?query=not-telemetry",
          scheme: "https",
        },
      },
      ...overrides,
    },
  };
}

test("maps measured descriptor map-entry arrays into narrow checks", () => {
  assert.deepEqual(parseExtAuthzCheck(request()), {
    mode: "authorize",
    caseId: "case-a",
    sessionId: "session-a",
    routeId: "route-a",
    requireCapability: true,
    credentialRequired: true,
    proxyAuthorization: "capability",
    method: "GET",
    host: "example.com",
    pathAndQuery: "/allowed?query=not-telemetry",
    scheme: "https",
  });
});

test("parses real proto-loader CheckRequest roundtrip objects into frozen narrow checks", async () => {
  const { authorizationService } = await loadExtAuthzDescriptor();
  const decoded = authorizationService.Check.requestDeserialize(
    authorizationService.Check.requestSerialize(request()),
  ) as unknown;
  const parsed = parseExtAuthzCheck(decoded);
  assert.deepEqual(parsed, {
    mode: "authorize",
    caseId: "case-a",
    sessionId: "session-a",
    routeId: "route-a",
    requireCapability: true,
    credentialRequired: true,
    proxyAuthorization: "capability",
    method: "GET",
    host: "example.com",
    pathAndQuery: "/allowed?query=not-telemetry",
    scheme: "https",
  });
  assert.equal(Object.isFrozen(parsed), true);
});

test("accepts mixed-case proxy authorization and rejects duplicate map-entry headers", () => {
  assert.equal(
    parseExtAuthzCheck(
      request({ request: { http: { headers: [{ key: "Proxy-Authorization", value: "capability" }] } } }),
    ).proxyAuthorization,
    "capability",
  );
  assert.throws(
    () =>
      parseExtAuthzCheck(
        request({
          request: {
            http: {
              headers: [
                { key: "proxy-authorization", value: "a" },
                { key: "proxy-authorization", value: "b" },
              ],
            },
          },
        }),
      ),
    ExtAuthzAdapterError,
  );
});

test("rejects malformed map entries", () => {
  assert.throws(
    () => parseExtAuthzCheck(request({ request: { http: { headers: [{ key: "proxy-authorization" }] } } })),
    ExtAuthzAdapterError,
  );
  assert.throws(
    () =>
      parseExtAuthzCheck(
        request({ request: { http: { headers: [Object.create({ key: "proxy-authorization", value: "x" })] } } }),
      ),
    ExtAuthzAdapterError,
  );
});

test("rejects unknown or mis-cased context and header entries", () => {
  assert.throws(
    () => parseExtAuthzCheck(request({ context_extensions: [...context, { key: "cogs.extra", value: "x" }] })),
    ExtAuthzAdapterError,
  );
  assert.throws(
    () =>
      parseExtAuthzCheck(
        request({ context_extensions: [{ key: "Cogs.mode", value: "authorize" }, ...context.slice(1)] }),
      ),
    ExtAuthzAdapterError,
  );
  assert.throws(
    () => parseExtAuthzCheck(request({ context_extensions: [...context, { key: "cogs.mode", value: "authorize" }] })),
    ExtAuthzAdapterError,
  );
  assert.throws(
    () => parseExtAuthzCheck(request({ request: { http: { headers: [{ key: "authorization", value: "secret" }] } } })),
    ExtAuthzAdapterError,
  );
});

test("rejects excessive, oversized, and control-character values", () => {
  assert.throws(
    () => parseExtAuthzCheck(request({ context_extensions: [...context, { key: "cogs.extra", value: "x" }] })),
    ExtAuthzAdapterError,
  );
  assert.throws(
    () =>
      parseExtAuthzCheck(
        request({
          context_extensions: context.map((entry) =>
            entry.key === "cogs.case_id" ? { ...entry, value: "a".repeat(129) } : entry,
          ),
        }),
      ),
    ExtAuthzAdapterError,
  );
  assert.throws(
    () =>
      parseExtAuthzCheck(
        request({
          context_extensions: context.map((entry) =>
            entry.key === "cogs.case_id" ? { ...entry, value: "bad\n" } : entry,
          ),
        }),
      ),
    ExtAuthzAdapterError,
  );
  assert.throws(
    () =>
      parseExtAuthzCheck(
        request({ request: { http: { headers: [{ key: "proxy-authorization", value: "a".repeat(8193) }] } } }),
      ),
    ExtAuthzAdapterError,
  );
  assert.throws(
    () => parseExtAuthzCheck(request({ request: { http: { path: `/${"a".repeat(2048)}` } } })),
    ExtAuthzAdapterError,
  );
});

test("rejects prototype polluted decoded objects", () => {
  const polluted = Object.create({ attributes: { context_extensions: context } });
  assert.throws(() => parseExtAuthzCheck(polluted), ExtAuthzAdapterError);
});

test("freezes parsed checks and rejects malformed response decisions", () => {
  const parsed = parseExtAuthzCheck(request());
  assert.equal(Object.isFrozen(parsed), true);
  assert.throws(() => buildExtAuthzResponse({ outcome: "allow", intentId: "bad/control\n" }), ExtAuthzAdapterError);
  assert.throws(() => buildExtAuthzResponse({ outcome: "allow" } as never), ExtAuthzAdapterError);
  assert.throws(() => buildExtAuthzResponse({ outcome: "deny", status: 500 } as never), ExtAuthzAdapterError);
  assert.throws(
    () => buildExtAuthzResponse(Object.create({ outcome: "allow", intentId: "intent-a" }) as never),
    ExtAuthzAdapterError,
  );
  const response = buildExtAuthzResponse({ outcome: "allow", intentId: "intent-a" }) as { readonly status: unknown };
  assert.equal(Object.isFrozen(response), true);
  assert.equal(Object.isFrozen(response.status), true);
});

test("builds intent metadata as dynamic metadata only", () => {
  assert.deepEqual(buildExtAuthzResponse({ outcome: "allow_capability" }), {
    status: { code: 0, message: "", details: [] },
    ok_response: {},
  });
  assert.deepEqual(buildExtAuthzResponse({ outcome: "allow", intentId: "intent-a" }), {
    status: { code: 0, message: "", details: [] },
    ok_response: {},
    dynamic_metadata: { fields: [{ key: "x-cogs-intent-id", value: { string_value: "intent-a" } }] },
  });
});

test("preserves only the bounded proxy challenge on 407", () => {
  assert.deepEqual(buildExtAuthzResponse({ outcome: "deny", status: 407 }), {
    status: { code: 7, message: "denied", details: [] },
    denied_response: {
      status: { code: 407 },
      headers: [
        { header: { key: "proxy-authenticate", value: 'Basic realm="cogs-session"' }, append: { value: false } },
      ],
      body: "",
    },
  });
  assert.deepEqual(buildExtAuthzResponse({ outcome: "deny", status: 403 }), {
    status: { code: 7, message: "denied", details: [] },
    denied_response: { status: { code: 403 }, headers: [], body: "" },
  });
});

test("descriptor roundtrip preserves exactly one proxy challenge on 407", async () => {
  const { authorizationService } = await loadExtAuthzDescriptor();
  const round = authorizationService.Check.responseDeserialize(
    authorizationService.Check.responseSerialize(buildExtAuthzResponse({ outcome: "deny", status: 407 })),
  ) as DenyRoundtrip;
  assert.equal(round.denied_response.status.code, "ProxyAuthenticationRequired");
  assert.equal(round.denied_response.headers.length, 1);
  assert.equal(round.denied_response.headers[0]?.header.key, "proxy-authenticate");
  assert.equal(round.denied_response.headers[0]?.header.value, 'Basic realm="cogs-session"');
  assert.equal(JSON.stringify(round).includes("proxy-authorization"), false);
  assert.equal(JSON.stringify(round).includes("x-cogs-intent-id"), false);
});

test("descriptor roundtrip keeps Cogs intent dynamic-only and upstream mutations empty", async () => {
  const { authorizationService } = await loadExtAuthzDescriptor();
  const round = authorizationService.Check.responseDeserialize(
    authorizationService.Check.responseSerialize(buildExtAuthzResponse({ outcome: "allow", intentId: "intent-a" })),
  ) as ExtAuthzRoundtrip;
  assert.equal(round.ok_response?.headers, undefined);
  assert.equal(round.ok_response?.headers_to_remove, undefined);
  assert.equal(round.dynamic_metadata.fields[0]?.key, "x-cogs-intent-id");
  assert.equal(round.dynamic_metadata.fields[0]?.value.string_value, "intent-a");
  assert.equal(JSON.stringify(round).includes("proxy-authorization"), false);
  assert.equal(JSON.stringify(round).includes("authorization"), false);
  assert.equal(JSON.stringify(round).includes("capability"), false);
});

interface DenyRoundtrip {
  readonly denied_response: {
    readonly status: { readonly code: string };
    readonly headers: ReadonlyArray<{ readonly header: { readonly key: string; readonly value: string } }>;
  };
}

interface ExtAuthzRoundtrip {
  readonly ok_response?: { readonly headers?: unknown; readonly headers_to_remove?: unknown };
  readonly dynamic_metadata: {
    readonly fields: ReadonlyArray<{ readonly key: string; readonly value: { readonly string_value?: string } }>;
  };
}
